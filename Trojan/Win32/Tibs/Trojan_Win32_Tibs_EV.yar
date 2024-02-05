
rule Trojan_Win32_Tibs_EV{
	meta:
		description = "Trojan:Win32/Tibs.EV,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {51 89 ce c1 e9 90 01 01 90 02 09 81 c1 90 01 04 81 90 03 01 01 c1 e9 90 01 04 90 02 03 8b 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}