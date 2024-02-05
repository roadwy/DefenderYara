
rule Trojan_Win32_Tibs_HI{
	meta:
		description = "Trojan:Win32/Tibs.HI,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c3 66 ad c1 e0 04 c1 e0 04 c1 e0 04 c1 e0 04 66 ad c1 c0 02 c1 c0 0b c1 c0 03 93 81 c3 } //00 00 
	condition:
		any of ($a_*)
 
}