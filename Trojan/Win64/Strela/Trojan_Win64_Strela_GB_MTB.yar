
rule Trojan_Win64_Strela_GB_MTB{
	meta:
		description = "Trojan:Win64/Strela.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 c7 44 24 28 88 13 00 00 48 c7 44 24 20 00 00 00 00 41 b9 10 00 00 00 31 c9 } //10
		$a_01_1 = {41 b8 00 30 00 00 41 b9 40 00 00 00 31 c9 } //1
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}