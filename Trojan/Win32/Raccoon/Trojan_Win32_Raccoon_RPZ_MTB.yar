
rule Trojan_Win32_Raccoon_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 c7 17 49 c1 c0 13 03 fa 09 0d 90 01 04 2b fa c1 c8 13 41 c1 cf 17 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}