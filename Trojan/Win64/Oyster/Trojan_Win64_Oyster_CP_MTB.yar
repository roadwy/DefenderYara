
rule Trojan_Win64_Oyster_CP_MTB{
	meta:
		description = "Trojan:Win64/Oyster.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 b8 fd d5 0d cc c7 5a c7 92 } //2
		$a_01_1 = {48 b8 2c 4d 5c 07 f6 66 f9 12 } //2
		$a_01_2 = {48 b8 e6 e3 f7 c2 33 54 ec 8f } //2
		$a_01_3 = {48 b8 26 44 fb 3e 9d 19 39 39 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}