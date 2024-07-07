
rule Trojan_Win32_Vidar_PBC_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 33 44 24 10 c7 05 90 01 08 2b f0 89 44 24 14 8b c6 c1 e0 04 89 44 24 10 8b 44 24 24 01 44 24 10 8b ce c1 e9 05 03 4c 24 28 8d 04 33 31 44 24 10 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}