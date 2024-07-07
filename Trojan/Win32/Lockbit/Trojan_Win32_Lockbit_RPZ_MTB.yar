
rule Trojan_Win32_Lockbit_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Lockbit.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b c3 c1 e0 04 89 44 24 14 83 f9 05 } //1
		$a_01_1 = {8d 34 2b 89 44 24 14 8b c3 c1 e8 05 89 44 24 10 83 f9 1b } //1
		$a_01_2 = {8b d7 c1 e2 04 89 54 24 14 8b 44 24 24 01 44 24 14 8b c7 c1 e8 05 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}