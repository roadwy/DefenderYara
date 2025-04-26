
rule Trojan_Win64_Rozena_NBK_MTB{
	meta:
		description = "Trojan:Win64/Rozena.NBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_1 = {50 41 59 4c 4f 41 44 3a } //1 PAYLOAD:
		$a_01_2 = {48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed } //1
		$a_01_3 = {e3 56 4d 31 c9 48 ff c9 41 8b 34 88 48 01 d6 48 31 c0 41 c1 c9 0d ac 41 01 c1 38 e0 75 f1 } //2
		$a_01_4 = {41 58 41 58 48 01 d0 5e 59 5a 41 58 41 59 41 5a 48 83 ec 20 41 52 ff e0 58 41 59 5a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=6
 
}