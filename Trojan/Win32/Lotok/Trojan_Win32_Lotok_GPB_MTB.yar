
rule Trojan_Win32_Lotok_GPB_MTB{
	meta:
		description = "Trojan:Win32/Lotok.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 59 66 49 52 5a 32 06 9c 50 b8 } //4
		$a_01_1 = {88 07 60 66 89 c8 66 89 c7 61 46 60 89 f3 89 da 61 47 9c 66 56 } //4
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4) >=8
 
}