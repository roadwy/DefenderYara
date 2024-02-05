
rule TrojanSpy_Win32_Broler_RC_dha{
	meta:
		description = "TrojanSpy:Win32/Broler.RC!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b fe c7 45 90 01 05 6a 90 01 01 6a 90 01 01 6a 90 01 01 e8 90 01 04 8b 45 90 01 01 32 04 37 6a 90 01 01 6a 90 01 01 6a 90 01 01 88 06 e8 90 01 04 8b 45 90 01 01 6a 90 01 01 c1 e0 90 01 01 6a 90 01 01 89 45 90 01 01 6a 90 01 01 e8 90 01 04 8b 45 90 01 01 6a 90 01 01 c1 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}