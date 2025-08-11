
rule Trojan_Win32_GuLoader_RBW_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 6f 66 74 77 61 72 65 5c 6a 65 7a 61 69 6c 5c 73 70 75 72 76 65 75 6e 67 65 72 6e 65 73 } //1 Software\jezail\spurveungernes
		$a_81_1 = {5c 70 6c 61 6e 6b 65 76 72 6b 65 74 5c 70 65 74 75 6e 69 61 } //1 \plankevrket\petunia
		$a_81_2 = {64 61 6d 70 73 6b 69 62 73 66 6f 72 62 69 6e 64 65 6c 73 65 20 62 72 6f 67 75 65 73 20 68 75 6d 6f 72 70 72 6f 6f 66 } //1 dampskibsforbindelse brogues humorproof
		$a_81_3 = {70 6f 73 6e 61 6e 69 61 6e } //1 posnanian
		$a_81_4 = {61 6e 76 65 6e 64 65 6c 73 65 73 66 6f 72 6d 61 61 6c 65 6e 65 73 20 63 6c 6f 73 65 6f 75 74 2e 65 78 65 } //1 anvendelsesformaalenes closeout.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}