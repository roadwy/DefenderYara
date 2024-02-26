
rule Trojan_Win32_Zenpak_GNP_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {29 d0 31 d0 89 c2 8d 05 90 01 04 31 20 83 c0 90 01 01 01 c2 b9 90 01 04 e2 90 01 01 e8 90 01 04 83 f2 90 01 01 b8 90 01 04 42 40 31 35 90 01 04 89 d0 42 31 1d 90 01 04 40 89 2d 90 01 04 29 d0 40 8d 05 90 01 04 01 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}