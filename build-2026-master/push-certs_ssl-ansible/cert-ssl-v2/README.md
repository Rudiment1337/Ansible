
# DYNAMIC INV
# FULL - SSL OPEN AND CLOSE certs ./files/*
# VAR GLOB ./default/main.yml

# PASSWORD { PFX ; JKS } - WIKI
# PLAYBOOK

deploy-ssl.yml

* RUN

ansible-playbook -i /etc/ansible/roles/cert-ssl/python_script/dynam_inv.py /etc/ansible/deplay-ssl.yml

* FLAG								 
									*   VAR

# is_crt - true/false							#  site_url - url web host
# is_pem - true/false							#  service_name - systemd daemon
# is_jks - true/false							#  service_named - service for copy ssl and reload   						
# is_pfx - true/false							#  certificate_valid_to - actual ssl
#									#  ssl_docker_name - name docker container
# 									#  ssl_cert_expected_not_after": - last date actual ssl

* OTHER

Инвентарь формируется динамически получая данные с NetBox.
В данном role происходит следующее:

1.0 - 
	Создание пользователя (ssl-cert),изменение группы файла (/etc/ssl/private/)
1.1 - 
	Копирование на хост сертификаты (определяется флагами)
2.0 - 
	Получение текушего ssl и сопоставление ssl с актуальным (url site host)
	Eсли возврат старого серта -> выполнение 3.0, если возврат актуального, то ОK
3.0 - 
	Выполнение перезапуска/перезагрузка службы

	Если служба не запущена, кфг битый, задача будет пропущена.

#				Сообщениен если служба не запущена

UNNING HANDLER [cert-ssl : Warn if service is stopped] ****************************************************************
ok: [172.26.1.11] => {
    "msg": "WARNING: The nginx service is NOT running on srv-opensearch!\nCurrent state: inactive.\nReload will be skipped. Please start the service manually.\n"
}

#
#				Сообщение если в кфг ошибка в синтаксисе

RUNNING HANDLER [cert-ssl : Check web server configuration] ************************************************************
fatal: [172.26.1.11]: FAILED! => {"changed": false, "cmd": ["nginx", "-t"], "delta": "0:00:00.005273", "end": "2026-07-22 08:48:20.473685", "failed_when_result": true, "msg": "non-zero return code", "rc": 1, "start": "2026-07-22 08:48:20.468412", "stderr": "2026/07/22 08:48:20 [emerg] 2895#2895: unknown directive \"akwdkawd\" in /etc/nginx/sites-enabled/opensearch:6\nnginx: configuration file /etc/nginx/nginx.conf test failed", "stderr_lines": ["2026/07/22 08:48:20 [emerg] 2895#2895: unknown directive \"akwdkawd\" in /etc/nginx/sites-enabled/opensearch:6", "nginx: configuration file /etc/nginx/nginx.conf test failed"], "stdout": "", "stdout_lines": []}

#
