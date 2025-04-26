
rule Spammer_Win32_Campsafe{
	meta:
		description = "Spammer:Win32/Campsafe,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 08 00 0c 00 00 "
		
	strings :
		$a_01_0 = {7b 72 63 70 74 5f 74 6f 7d } //1 {rcpt_to}
		$a_01_1 = {7b 6d 61 69 6c 5f 66 72 6f 6d 7d } //1 {mail_from}
		$a_01_2 = {7b 65 78 74 5f 69 70 7d } //1 {ext_ip}
		$a_01_3 = {7b 6d 66 5f 64 6f 6d 61 69 6e 7d } //1 {mf_domain}
		$a_01_4 = {48 45 4c 4f 20 7b 4d 59 53 45 52 56 45 52 7d } //1 HELO {MYSERVER}
		$a_01_5 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c 7b 4d 41 49 4c 5f 46 52 4f 4d 7d 3e } //1 MAIL FROM:<{MAIL_FROM}>
		$a_01_6 = {52 43 50 54 20 54 4f 3a 3c 7b 4d 41 49 4c 5f 54 4f 7d 3e } //1 RCPT TO:<{MAIL_TO}>
		$a_01_7 = {25 64 2e 25 64 2e 25 64 2e 25 64 2e 69 6e 2d 61 64 64 72 2e 61 72 70 61 } //1 %d.%d.%d.%d.in-addr.arpa
		$a_01_8 = {67 6e 52 65 63 6f 6e 6e 65 63 74 69 6f 6e 4c 69 6d 69 74 4d 58 } //1 gnReconnectionLimitMX
		$a_01_9 = {67 6e 44 6e 73 41 6e 73 77 65 72 54 69 6d 65 4f 75 74 } //1 gnDnsAnswerTimeOut
		$a_01_10 = {67 6e 44 65 6c 61 79 32 35 } //1 gnDelay25
		$a_01_11 = {5b 25 64 2e 25 64 2e 25 64 2e 25 64 5d } //1 [%d.%d.%d.%d]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=8
 
}