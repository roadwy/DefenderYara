
rule Trojan_BAT_AgentTesla_FI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {69 70 61 64 64 72 65 73 73 2f 61 70 69 2f 61 64 6d 69 6e 2f 63 6f 6e 66 69 67 75 72 61 74 69 6f 6e 2f 76 31 2f 63 6f 6e 66 65 72 65 6e 63 65 2f 31 2f } //1 ipaddress/api/admin/configuration/v1/conference/1/
		$a_81_1 = {2e 4e 65 77 74 6f 6e 73 6f 66 74 2e 4a 73 6f 6e 2e 64 6c 6c } //1 .Newtonsoft.Json.dll
		$a_81_2 = {77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //1 www.google.com
		$a_81_3 = {41 70 70 31 2e 50 72 6f 70 65 72 74 69 65 73 } //1 App1.Properties
		$a_03_4 = {41 70 70 31 2e 52 65 73 6f 75 72 63 65 73 2e [0-19] 2e 64 6c 6c } //1
		$a_81_5 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
		$a_81_6 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_7 = {61 64 6d 69 6e 31 32 33 } //1 admin123
		$a_81_8 = {52 65 61 64 54 6f 45 6e 64 } //1 ReadToEnd
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_03_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}
rule Trojan_BAT_AgentTesla_FI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.FI!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 17 58 0a 06 20 00 01 00 00 5d 0a 08 11 06 06 94 58 0c 08 20 00 01 00 00 5d 0c 11 06 06 94 13 04 11 06 06 11 06 08 94 9e 11 06 08 11 04 9e 11 06 11 06 06 94 11 06 08 94 58 20 00 01 00 00 5d 94 0d 11 07 07 02 07 91 09 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 13 0a 11 0a 2d a2 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}