
rule Trojan_Win32_Dridex_PG_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {3b c1 74 19 0f 90 02 06 8b c3 00 9a 90 02 04 2b c1 83 90 02 02 a3 90 02 04 83 90 02 02 83 90 02 02 7f 90 01 01 85 f6 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}