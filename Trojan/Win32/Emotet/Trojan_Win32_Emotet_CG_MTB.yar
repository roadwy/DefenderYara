
rule Trojan_Win32_Emotet_CG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 c0 b9 02 68 00 00 2b c8 89 0d 90 01 04 83 c4 14 b9 01 10 00 00 2b c8 89 0d 90 01 04 6a 41 59 2b c8 89 0d 90 01 04 6a 02 59 2b c8 89 0d 90 01 04 b9 04 80 00 00 2b c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}