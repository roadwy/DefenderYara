
rule Trojan_Win32_Zenpak_CZ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 f2 88 d0 a2 } //2
		$a_01_1 = {01 20 4a b8 } //2
		$a_03_2 = {31 d0 8d 05 90 01 04 31 28 89 d0 89 d8 90 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}