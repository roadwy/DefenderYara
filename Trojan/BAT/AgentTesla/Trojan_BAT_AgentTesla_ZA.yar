
rule Trojan_BAT_AgentTesla_ZA{
	meta:
		description = "Trojan:BAT/AgentTesla.ZA,SIGNATURE_TYPE_PEHSTR,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {6c 61 7a 61 72 75 73 34 } //1 lazarus4
		$a_01_1 = {45 00 76 00 69 00 6c 00 62 00 6f 00 79 00 } //1 Evilboy
		$a_01_2 = {52 53 4d 44 5f 45 43 } //1 RSMD_EC
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //1 Rfc2898DeriveBytes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}