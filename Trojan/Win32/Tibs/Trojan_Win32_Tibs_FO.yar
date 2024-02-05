
rule Trojan_Win32_Tibs_FO{
	meta:
		description = "Trojan:Win32/Tibs.FO,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff e0 8b 04 24 66 31 c0 8b 10 81 f2 90 01 04 66 81 fa 90 01 02 74 07 2d 00 10 00 00 eb ea 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}