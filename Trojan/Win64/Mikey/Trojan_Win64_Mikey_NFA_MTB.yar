
rule Trojan_Win64_Mikey_NFA_MTB{
	meta:
		description = "Trojan:Win64/Mikey.NFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 74 50 72 6f 70 57 72 69 74 65 49 6e 74 } //2 etPropWriteInt
		$a_01_1 = {48 8d 6c 24 b9 48 81 ec c0 00 00 00 48 8b 05 b9 b8 01 00 48 33 c4 48 89 45 3f 4c 8b f1 83 fa 01 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}