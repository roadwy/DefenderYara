
rule Trojan_Win32_Tibs_IG{
	meta:
		description = "Trojan:Win32/Tibs.IG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c0 01 83 c0 01 8b 18 be 90 01 04 ff 94 1e 90 01 04 61 b9 90 01 02 00 00 c9 c2 90 01 01 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}