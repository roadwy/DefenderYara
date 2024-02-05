
rule TrojanDownloader_Win32_Votwup_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Votwup.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {80 7d fb 01 75 90 01 01 81 ff b8 0b 00 00 76 90 01 01 6a 01 6a 00 90 00 } //03 00 
		$a_03_1 = {6a 02 6a 00 6a 00 e8 90 01 02 ff ff e8 90 01 02 ff ff 3d b7 00 00 00 75 05 90 00 } //01 00 
		$a_01_2 = {6d 73 5f 69 65 } //01 00 
		$a_01_3 = {3a 2a 3a 45 6e 61 62 6c 65 64 3a } //00 00 
	condition:
		any of ($a_*)
 
}