
rule Trojan_Win32_RedLineStealer_PH_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 18 8b c7 d3 e8 89 44 24 10 8b 44 24 34 01 44 24 10 90 01 08 8b cf c1 e1 90 01 01 03 4c 24 40 89 15 90 01 04 33 4c 24 10 33 4c 24 14 2b d9 4d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}