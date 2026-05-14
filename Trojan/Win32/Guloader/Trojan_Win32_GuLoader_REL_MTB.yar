
rule Trojan_Win32_GuLoader_REL_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.REL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {72 65 74 75 72 62 69 6c 6c 65 74 74 65 6e } //1 returbilletten
		$a_81_1 = {6b 61 74 74 65 6a 65 72 6e 65 73 20 6f 75 74 74 72 75 6d 70 } //1 kattejernes outtrump
		$a_81_2 = {70 72 6f 67 72 61 6d 66 6c 61 64 65 72 20 6b 6f 6d 70 69 6c 65 72 65 } //1 programflader kompilere
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}