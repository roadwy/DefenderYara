
rule Trojan_Win32_Zenpak_ABC_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ABC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 10 31 30 42 89 2d ?? ?? ?? ?? 31 c2 83 f2 02 29 c2 ba 08 00 00 00 8d 05 ?? ?? ?? ?? 89 18 b9 02 00 00 00 e2 } //4
		$a_01_1 = {55 89 e5 8a 45 0c 8a 4d 08 b2 01 88 cc 02 25 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}