
rule TrojanDownloader_Win32_Dadobra_BO{
	meta:
		description = "TrojanDownloader:Win32/Dadobra.BO,SIGNATURE_TYPE_PEHSTR,0d 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {68 7e 9b 41 00 64 ff 30 64 89 20 b8 4c b7 41 00 ba 94 9b 41 00 e8 fb 9d fe ff 6a 00 68 44 b7 41 00 68 38 95 41 00 8d 45 c0 50 b9 03 00 00 00 ba 01 00 00 00 a1 4c b7 41 00 e8 43 a2 fe ff 8d 45 c0 50 } //01 00 
		$a_01_1 = {53 43 50 4e 45 57 43 54 2e 42 49 4e } //01 00 
		$a_01_2 = {53 43 50 4e 45 55 52 4c 2e 42 49 4e } //01 00 
		$a_01_3 = {53 43 50 4e 45 4c 4f 47 2e 42 49 4e } //00 00 
	condition:
		any of ($a_*)
 
}