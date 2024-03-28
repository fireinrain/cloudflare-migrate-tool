# 将cloudflare一个账号下的某个域名的dns 迁移到另一个或者同一个账号下的其他域名
# 将cloudflare一个账号下的某个域名的origin rules 迁移到另一个或者同一个账号下的其他域名
import re
import requests


class CloudflareMigrator:
    def __init__(self, source_account_email: str, source_api_key: str, source_domain: str,
                 target_account_email: str, target_api_key: str, target_domain: str):
        self.source_account_email = source_account_email
        self.source_api_key = source_api_key
        self.target_account_email = target_account_email
        self.target_api_key = target_api_key
        self.source_domain = source_domain
        self.target_domain = target_domain
        self.source_zone_id = CloudflareMigrator.get_domain_zone_id(source_account_email, source_api_key, source_domain)
        self.target_zone_id = CloudflareMigrator.get_domain_zone_id(target_account_email, target_api_key, target_domain)

    # 获取domain zone id
    @staticmethod
    def get_domain_zone_id(email: str, api_key: str, domain: str) -> str:
        headers = {
            'X-Auth-Email': email,
            'X-Auth-Key': api_key,
            'Content-Type': 'application/json'
        }
        url = f'https://api.cloudflare.com/client/v4/zones?name={domain}'
        response = requests.get(url, headers=headers)
        return response.json()['result'][0]['id']

    def get_dns_config(self, email: str, api_key: str, domain: str) -> []:
        headers = {
            'X-Auth-Email': email,
            'X-Auth-Key': api_key,
            'Content-Type': 'application/json'
        }
        zone_id = CloudflareMigrator.get_domain_zone_id(email, api_key, domain)
        url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records'
        response = requests.get(url, headers=headers)
        dns_records = []
        for record in response.json()['result']:
            dns_records.append({
                'Type': record['type'],
                'Name': record['name'],
                'Content': record['content'],
                'Proxied': record['proxied'],
                'Comment': record['comment'],
            })
        return dns_records

    def add_dns2_domain(self, email: str, api_key: str, domain: str, record_type: str, prefix: str, record_content: str,
                        proxied: bool,
                        comment: str):
        headers = {
            'X-Auth-Email': email,
            'X-Auth-Key': api_key,
            'Content-Type': 'application/json'
        }
        zone_id = CloudflareMigrator.get_domain_zone_id(email, api_key, domain)
        url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records'
        config_domain = prefix + '.' + domain
        data = {
            'type': record_type,
            'name': config_domain,
            'content': record_content,
            'ttl': 1,
            'proxied': proxied,
            'comment': comment,
        }
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            print(f'Successfully: {config_domain} {record_type} {record_content}')
        else:
            print(f'Failed: {config_domain} {record_type} {record_content}')

    # 迁移dns记录
    def migrate_dns_records(self):
        # 只迁移A/AAA/CNAME DNS记录
        print(f'***目前只做A/AAAA/CNAME DNS记录迁移***')
        source_config_json = self.get_dns_config(self.source_account_email, self.source_api_key, self.source_domain)

        for config in source_config_json:
            return_domain = config['Name']
            record_type = config['Type']
            record_content = config['Content']
            proxied = config['Proxied']
            comment = config['Comment']

            try:
                prefix = re.findall('(.*)\.' + self.source_domain, return_domain)[0]
                self.add_dns2_domain(self.target_account_email, self.target_api_key, self.target_domain, record_type,
                                     prefix, record_content, proxied, comment)
            except Exception as e:
                print(f"Error occurred: {e}")
                print(f'{return_domain},类型: {record_type},内容: {record_content}')
                print(f"可能存在MX，NS，TXT记录，不做迁移处理")
                print('---------------------------------')

        print(f"🎉🎉!Domain: {self.source_domain} DNS(CNAME/A/AAAA) record has been copyed to {self.target_domain}")

    # 迁移rules记录
    def migrate_origin_rules(self):
        # 注意免费的cf用户 每个domain 只有10个origin rule
        print("***注意免费的cf用户 每个domain 只有10个origin rule***")
        rules = self.get_origin_rules(self.source_account_email, self.source_api_key, self.source_zone_id)
        if rules[0]:
            print(f"源域名: {self.source_domain},已设置:{len(rules[1])}条 origin rule")
        else:
            print(f"源域名: {self.source_domain}暂时没设置origin rule，不需要迁移")
            return

        # 新域名获取rules
        target_rules = self.get_origin_rules(self.target_account_email, self.target_api_key, self.target_zone_id)
        if target_rules[0]:
            print(f"目标域名: {self.target_domain},已设置:{len(target_rules[1])}条 origin rule,正在更新origin rule")
            # 更新rules
            target_rules[1].extend(rules[1])
            new_rules = target_rules[1]
            self.update_origin_rules(self.target_account_email, self.target_api_key, self.target_zone_id, target_rules[0],
                                     new_rules)
        else:
            print(f"目标域名: {self.target_domain}暂时没设置origin rule，正在迁移origin rule")
            # 先创建http_request_origin
            zone_rule_id = self.create_zone_origin_rule(self.target_account_email, self.target_api_key,
                                                        self.target_zone_id)
            self.update_origin_rules(self.target_account_email, self.target_api_key, self.target_zone_id, zone_rule_id,
                                     rules[1])
            # 然后再迁移
        print(f'🎉🎉！迁移origin rule成功.')

    def update_origin_rules(self, email, api_key, target_zone_id, target_rule_id: str, rule_list: []):
        '''
        文档参考： https://developers.cloudflare.com/rules/origin-rules/create-api/
        :param email:
        :param api_key:
        :param target_zone_id:
        :param target_rule_id:
        :param rule_list:
        :return:
        '''
        url = f"https://api.cloudflare.com/client/v4/zones/{target_zone_id}/rulesets/{target_rule_id}/rules"
        headers = {
            'X-Auth-Email': email,
            'X-Auth-Key': api_key,
            'Content-Type': 'application/json'
        }
        for rule in rule_list:
            expression_ = rule['expression']
            new_exp = expression_.replace(self.source_domain, self.target_domain)
            rule['expression'] = new_exp


        rules = []
        for rule in rule_list:
            r = {}
            r['action'] = rule['action']
            r['expression'] = rule['expression']
            r['description'] = rule['description']
            r['action_parameters'] = rule['action_parameters']
            rules.append(r)
        for r in rules:
            response = requests.request("POST", url, json=r, headers=headers)
            response.raise_for_status()
            print(response.json())
            print(f'迁移origin rule完成: {r}')

    def create_zone_origin_rule(self, email, api_key, zone_id) -> str:
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets"
        headers = {
            'X-Auth-Email': email,
            'X-Auth-Key': api_key,
            'Content-Type': 'application/json'
        }
        payload = {
            "description": "My ruleset to execute managed rulesets",
            "kind": "zone",
            "name": "my rule set",
            "phase": "http_request_origin",
            "rules": []
        }
        response = requests.request("POST", url, json=payload, headers=headers)
        response.raise_for_status()
        # print(response.json())
        return response.json()['result']['id']

    def get_origin_rules(self, email, api_key, zone_id) -> ():
        headers = {
            'X-Auth-Email': email,
            'X-Auth-Key': api_key,
            'Content-Type': 'application/json'
        }
        origin_rules_url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets'
        response = requests.get(origin_rules_url, headers=headers)
        origin_rules = response.json()['result']
        for rule in origin_rules:
            if rule['phase'] == 'http_request_origin':
                http_request_origin_rule_id = rule['id']
                source_rule_set_url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{http_request_origin_rule_id}'
                response = requests.get(source_rule_set_url, headers=headers)
                response.raise_for_status()
                if 'rules' not in response.json()['result']:
                    print(f'当前域名还未设置origin rules,zone id: {zone_id}')
                    return http_request_origin_rule_id, []
                else:
                    rule_set = response.json()['result']['rules']
                    return http_request_origin_rule_id, rule_set
        return '', []

    def purge_source_account_dns(self):
        self.recursive_delete_records(self.source_account_email, self.source_api_key, self.source_zone_id)

    def purge_target_account_dns(self):
        self.recursive_delete_records(self.target_account_email, self.target_api_key, self.target_zone_id)

    def recursive_delete_records(self, email, api_key, zone_id):
        headers = {
            'X-Auth-Email': email,
            'X-Auth-Key': api_key,
            'Content-Type': 'application/json'
        }
        url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records'
        response = requests.get(url, headers=headers)
        data = response.json()

        for record in data['result']:
            record_id = record['id']
            delete_url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}'
            requests.delete(delete_url, headers=headers)
            print(f'Deleted DNS record: {record["name"]} ({record["type"]})')

        if data['result_info']['count'] > 50:
            self.recursive_delete_records(email, api_key, zone_id)  # 继续递归删除


if __name__ == '__main__':

    migrator = CloudflareMigrator('xxx@gmail.com', 'xxxxx', 'xxxxx.xyz',
                                  'xxxxx@gmail.com', 'xxxxx', 'xxxxx.eu')

    # 迁移dns记录
    migrator.migrate_dns_records()

    # 迁移origin rules
    migrator.migrate_origin_rules()

    # 以下方法请慎用
    # migrator.purge_target_account_dns()
    # migrator.purge_target_account_dns()

