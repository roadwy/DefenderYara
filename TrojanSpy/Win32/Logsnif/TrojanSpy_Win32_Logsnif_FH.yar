
rule TrojanSpy_Win32_Logsnif_FH{
	meta:
		description = "TrojanSpy:Win32/Logsnif.FH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 79 ff 69 ff 90 01 02 00 00 66 31 7c 4a fe 66 8b 3c 4a 66 01 7c 4a fe e2 e7 90 00 } //01 00 
		$a_01_1 = {6a 00 90 90 90 90 90 90 ff d0 ff 56 04 ff d0 } //00 00 
	condition:
		any of ($a_*)
 
}