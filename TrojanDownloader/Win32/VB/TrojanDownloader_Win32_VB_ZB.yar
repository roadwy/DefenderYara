
rule TrojanDownloader_Win32_VB_ZB{
	meta:
		description = "TrojanDownloader:Win32/VB.ZB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 6f 72 6d 31 00 19 01 00 42 00 23 3e 04 00 00 6c 74 00 00 36 04 00 00 00 00 01 00 02 00 20 20 10 00 00 00 00 00 e8 02 00 00 26 00 00 00 10 10 10 00 00 00 00 00 28 01 00 00 0e 03 00 00 28 00 00 00 20 00 00 00 40 00 00 00 01 00 04 00 00 00 00 00 80 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 80 00 00 00 80 80 00 80 00 00 00 80 00 80 00 80 80 00 00 80 80 80 00 c0 c0 c0 00 00 00 ff 00 00 ff 00 00 00 ff ff 00 ff 00 00 00 ff 00 ff 00 ff ff 00 00 ff ff } //01 00 
		$a_01_1 = {77 77 77 77 77 77 77 77 77 77 77 77 77 70 00 00 7f bf ff bf ff bf ff bf ff bf ff bf ff 70 00 00 7f ff ff ff bf ff bf ff bf ff bf ff bf 70 00 00 78 ff ff bf ff bf ff bf ff bf ff bf f8 70 00 00 7f 8f bf ff bf ff bf ff bf ff bf ff 8f 70 00 00 7f b8 ff ff ff bf ff bf ff bf ff b8 ff 70 00 00 7f ff 8f ff bf f8 88 88 bf ff bf 8f bf 70 00 00 7f ff f8 bf ff 87 77 77 88 bf f8 bf ff 70 00 00 7f ff bf 8f f8 7f ff ff 78 8f 8f ff bf 70 00 00 7f ff ff b8 87 bf bf bf f7 88 ff bf ff 70 00 00 } //01 00 
		$a_01_2 = {7f ff ff f8 7f ff ff ff bf 78 bf ff bf 70 00 00 7f ff ff 87 ff ff ff ff ff b7 8f bf ff 70 00 00 7f ff f8 7f ff ff ff ff ff ff 78 ff bf 70 00 00 7f ff 87 ff ff ff ff ff ff bf f7 8f ff 70 00 00 7f f8 7f ff ff ff ff ff ff ff bf 78 bf 70 00 00 7f 87 ff ff ff ff ff ff ff ff ff b7 8f 70 00 00 78 7f ff ff ff ff ff ff ff ff ff ff 78 70 00 00 77 ff ff ff ff ff ff ff ff ff ff bf f7 70 00 00 7f ff ff ff ff ff ff ff ff ff ff ff bf 70 00 00 77 77 77 77 77 77 77 77 77 77 77 77 77 70 } //01 00 
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_02_4 = {55 52 4c 00 4c 6f 63 61 6c 46 69 6c 65 6e 61 6d 65 00 90 02 10 e9 e9 e9 e9 cc cc cc cc cc cc cc cc cc cc cc cc 55 8b ec 83 ec 0c 90 00 } //01 00 
		$a_00_5 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //00 00  MSVBVM60.DLL
	condition:
		any of ($a_*)
 
}