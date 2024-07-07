
rule Trojan_Linux_CuttleFish_A_MTB{
	meta:
		description = "Trojan:Linux/CuttleFish.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 6e 74 65 72 66 61 63 65 20 2d 6b 20 6b 69 6c 6c 6f 6c 64 20 61 67 65 6e 74 } //1 interface -k killold agent
		$a_01_1 = {73 6e 69 66 66 65 72 20 6e 69 63 } //1 sniffer nic
		$a_01_2 = {2f 74 6d 70 2f 2e 70 75 74 69 6e } //1 /tmp/.putin
		$a_01_3 = {68 74 74 70 5f 72 75 6c 65 5f 68 65 61 72 74 74 69 6d 65 } //1 http_rule_hearttime
		$a_01_4 = {68 74 74 70 5f 68 69 6a 61 63 6b 5f 68 65 61 72 74 74 69 6d 65 } //1 http_hijack_hearttime
		$a_01_5 = {2f 74 6d 70 2f 74 68 63 6f 6e 66 69 67 6a 73 } //1 /tmp/thconfigjs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}