
rule Trojan_Win32_Chapak_GNT_MTB{
	meta:
		description = "Trojan:Win32/Chapak.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {fa 1c 77 48 81 ad 90 01 04 44 13 5f 67 35 90 01 04 81 85 90 01 04 44 13 5f 67 c1 eb 90 01 01 bb 90 01 04 81 ad 90 01 04 a4 b5 43 1d 81 85 90 01 04 a4 b5 43 1d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}