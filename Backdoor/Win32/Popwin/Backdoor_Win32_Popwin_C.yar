
rule Backdoor_Win32_Popwin_C{
	meta:
		description = "Backdoor:Win32/Popwin.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {e8 56 f5 ff ff 8b 90 01 02 30 40 00 8b 90 01 02 30 40 00 8b 90 01 02 30 40 00 83 c4 0c 85 c0 74 19 50 6a 00 68 01 04 10 00 ff d7 8b e8 6a 01 55 ff d6 6a 00 55 ff d6 55 ff d3 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}