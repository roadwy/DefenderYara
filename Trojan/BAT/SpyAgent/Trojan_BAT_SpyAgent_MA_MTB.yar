
rule Trojan_BAT_SpyAgent_MA_MTB{
	meta:
		description = "Trojan:BAT/SpyAgent.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_03_0 = {06 02 07 6f ?? ?? ?? 0a 03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d1 6f ?? ?? ?? 0a 26 07 17 58 0b 07 02 6f ?? ?? ?? 0a 32 d5 06 6f ?? ?? ?? 0a 2a } //1
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_2 = {53 74 72 69 6e 67 44 65 63 72 79 70 74 } //1 StringDecrypt
		$a_81_3 = {52 65 71 75 65 73 74 43 6f 6e 6e 65 63 74 69 6f 6e } //1 RequestConnection
		$a_81_4 = {43 72 65 61 74 65 53 68 61 64 6f 77 43 6f 70 79 } //1 CreateShadowCopy
		$a_81_5 = {67 65 74 5f 55 52 4c } //1 get_URL
		$a_81_6 = {67 65 74 5f 49 50 } //1 get_IP
		$a_81_7 = {67 65 74 5f 50 61 73 73 77 6f 72 64 } //1 get_Password
		$a_81_8 = {67 65 74 5f 67 65 6f 70 6c 75 67 69 6e 5f 63 6f 75 6e 74 72 79 43 6f 64 65 } //1 get_geoplugin_countryCode
		$a_81_9 = {67 65 74 5f 48 74 74 70 } //1 get_Http
		$a_81_10 = {67 65 74 5f 4e 61 6d 65 4f 66 42 72 6f 77 73 65 72 } //1 get_NameOfBrowser
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=11
 
}