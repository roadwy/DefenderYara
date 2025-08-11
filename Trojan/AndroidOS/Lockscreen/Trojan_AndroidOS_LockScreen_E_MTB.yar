
rule Trojan_AndroidOS_LockScreen_E_MTB{
	meta:
		description = "Trojan:AndroidOS/LockScreen.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {12 04 07 05 6e 10 08 00 05 00 0c 05 52 55 02 00 12 26 dd 05 05 02 32 54 08 00 12 14 01 41 01 14 39 04 05 00 28 e2 12 04 28 fa 07 04 6e 10 09 00 04 00 0c 04 07 42 07 24 1a 05 6a 00 13 06 80 00 6e 30 13 00 54 06 0c 04 07 43 22 04 3b 00 } //1
		$a_01_1 = {6e 20 47 00 87 00 0a 07 38 07 1e 00 22 07 07 00 07 7e 07 e7 07 e8 07 19 1a 0a 6c 00 71 10 40 00 0a 00 0c 0a 70 30 0d 00 98 0a 07 74 07 47 15 08 00 10 6e 20 0e 00 87 00 0c 07 07 17 07 48 6e 20 0b 00 87 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}