
rule TrojanDownloader_Win32_Waski_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/Waski.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 06 8b 55 90 01 01 c1 c2 90 01 01 03 f2 8b 0e c1 c1 90 01 01 83 e1 90 01 01 03 c1 4b 89 07 ba 90 01 04 81 f2 90 01 04 03 fa 85 db 0f 84 90 01 04 8b 06 8b 55 90 01 01 c1 ca 90 01 01 03 f2 8b 0e c1 c1 90 01 01 83 e1 90 01 01 03 c1 4b 89 07 ba 90 01 04 81 f2 90 01 04 03 fa 85 db 75 90 00 } //01 00 
		$a_02_1 = {8b 03 03 c6 ba 90 01 04 81 f2 90 01 04 03 da 2d 90 01 04 89 45 90 01 01 03 cd 51 e8 90 01 04 57 59 59 2b cd 8b 55 90 01 01 81 f2 90 01 04 03 d1 3b d1 0f 85 90 01 04 2b d1 49 3b ca 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}