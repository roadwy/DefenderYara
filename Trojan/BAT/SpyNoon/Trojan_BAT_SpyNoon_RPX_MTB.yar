
rule Trojan_BAT_SpyNoon_RPX_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {38 00 35 00 2e 00 32 00 30 00 39 00 2e 00 31 00 37 00 36 00 2e 00 31 00 32 00 36 00 } //1 85.209.176.126
		$a_01_1 = {42 00 4c 00 41 00 43 00 4b 00 4c 00 49 00 53 00 54 00 } //1 BLACKLIST
		$a_01_2 = {42 61 69 74 44 72 6f 70 70 65 72 } //1 BaitDropper
		$a_01_3 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
		$a_01_4 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}