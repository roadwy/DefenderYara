
rule Trojan_Win32_GuLoader_RBV_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {65 6c 65 66 61 6e 74 68 75 65 72 6e 65 20 65 6e 65 68 65 72 72 65 64 6d 6d 65 73 } //1 elefanthuerne eneherredmmes
		$a_81_1 = {67 72 61 6d 6d 61 74 69 6b 65 72 6e 65 73 } //1 grammatikernes
		$a_81_2 = {63 61 6c 7a 6f 6e 65 } //1 calzone
		$a_81_3 = {66 75 72 63 75 6c 61 2e 65 78 65 } //1 furcula.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}