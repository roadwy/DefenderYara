
rule Trojan_Win32_Raccoon_PG_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 6a 00 e8 90 01 04 2b d8 90 02 0a 2b d8 8b 45 90 01 01 31 18 6a 00 90 02 0a 8b 5d e8 83 c3 04 2b d8 90 02 0a 2b d8 6a 00 90 02 08 2b d8 89 5d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}