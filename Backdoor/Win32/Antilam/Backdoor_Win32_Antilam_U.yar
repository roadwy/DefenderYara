
rule Backdoor_Win32_Antilam_U{
	meta:
		description = "Backdoor:Win32/Antilam.U,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {54 00 46 00 52 00 4d 00 46 00 49 00 4c 00 45 00 4d 00 41 00 4e 00 41 00 47 00 45 00 52 00 } //02 00  TFRMFILEMANAGER
		$a_01_1 = {53 70 64 52 65 6d 6f 76 65 57 61 6c 6c 50 61 70 65 72 43 6c 69 63 6b } //03 00  SpdRemoveWallPaperClick
		$a_01_2 = {53 70 64 41 63 74 43 72 61 7a 79 43 6c 69 63 6b } //03 00  SpdActCrazyClick
		$a_00_3 = {54 00 46 00 52 00 4d 00 45 00 58 00 54 00 52 00 41 00 46 00 55 00 4e 00 } //00 00  TFRMEXTRAFUN
	condition:
		any of ($a_*)
 
}