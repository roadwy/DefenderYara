
rule TrojanDownloader_Win32_Banload_BGU{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 00 68 00 6f 00 6d 00 70 00 73 00 6f 00 6e 00 2e 00 73 00 65 00 79 00 } //01 00  thompson.sey
		$a_80_1 = {42 41 49 58 41 4e 44 4f 5f 4e 4f 5f 50 43 } //BAIXANDO_NO_PC  01 00 
		$a_01_2 = {39 00 30 00 36 00 37 00 35 00 36 00 35 00 35 00 44 00 46 00 34 00 } //01 00  90675655DF4
		$a_01_3 = {03 04 9e 03 84 9d f0 fb ff ff 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 } //00 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}