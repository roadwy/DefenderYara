
rule Trojan_Win32_Vidar_YAA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e0 8b cf c1 e9 05 03 8c 24 90 01 04 03 84 24 90 01 04 89 15 90 01 04 33 c1 8b 4c 24 14 03 cf 33 c1 2b e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}