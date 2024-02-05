
rule Trojan_Win32_Tibs_HQ{
	meta:
		description = "Trojan:Win32/Tibs.HQ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 cb c3 ad 35 90 01 04 ab e2 f7 c3 8b 44 24 90 01 01 c1 e8 90 01 01 c1 e8 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}