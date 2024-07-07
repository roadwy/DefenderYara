
rule Trojan_Win32_Raccoon_PD_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8d 4c 24 90 01 01 89 44 24 90 01 01 e8 90 01 04 8b 4c 24 90 01 01 33 4c 24 90 01 01 89 35 90 01 04 31 4c 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 4b 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}