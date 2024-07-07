
rule Trojan_Win32_Vidar_PBD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 03 c5 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 4c 24 10 33 4c 24 18 8d 44 24 28 89 4c 24 10 e8 90 01 04 8b 44 24 38 29 44 24 14 83 ef 01 8b 4c 24 28 0f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}