
rule Trojan_Win32_Raccoon_PB_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 6a 00 e8 90 01 04 03 d8 6a 00 e8 90 01 04 2b d8 6a 00 e8 90 01 04 03 d8 8b 45 90 01 01 31 18 83 45 ec 90 01 01 6a 00 e8 90 01 04 bb 04 00 00 00 2b d8 6a 00 e8 90 01 04 03 d8 01 5d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}