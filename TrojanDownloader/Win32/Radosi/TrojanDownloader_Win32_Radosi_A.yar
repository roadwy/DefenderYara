
rule TrojanDownloader_Win32_Radosi_A{
	meta:
		description = "TrojanDownloader:Win32/Radosi.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 61 62 65 6c 31 78 00 01 01 34 00 4f 20 61 72 71 75 69 76 6f 20 65 73 74 e1 20 64 61 6e 69 66 69 63 61 64 6f 20 65 20 6e e3 6f } //01 00 
		$a_03_1 = {4e 00 61 00 6d 00 65 00 53 00 70 00 61 00 63 00 65 00 90 02 06 69 00 74 00 65 00 6d 00 73 00 90 02 06 43 00 6f 00 70 00 79 00 48 00 65 00 72 00 65 00 90 00 } //01 00 
		$a_03_2 = {6a 67 8d 85 fc fa ff ff 50 ff 15 90 01 04 6a 70 8d 8d dc fa ff ff 51 ff 15 90 01 04 6a 63 90 00 } //01 00 
		$a_03_3 = {6a 5c 8d 95 7c fd ff ff 52 ff 15 90 01 04 6a 47 8d 85 5c fd ff ff 50 ff 15 90 01 04 6a 62 8d 8d 3c fd ff ff 51 90 00 } //01 00 
		$a_03_4 = {6a 70 8d 85 fc fb ff ff 50 ff 15 90 01 04 6a 3f 8d 8d dc fb ff ff 51 ff 15 90 01 04 6a 41 8d 95 bc fb ff ff 52 ff 15 90 01 04 6a 31 8d 85 9c fb ff ff 90 00 } //01 00 
		$a_03_5 = {6a 70 8d 8d 90 01 01 fb ff ff 51 ff 15 90 01 04 6a 3f 8d 95 90 01 01 fb ff ff 52 ff 15 90 01 04 6a 41 8d 85 90 01 01 fb ff ff 50 ff 15 90 01 04 6a 31 8d 8d 90 00 } //01 00 
		$a_01_6 = {ff d6 8d 55 c4 6a 67 52 ff d6 8d 45 a4 6a 75 50 ff d6 8d 4d 84 6a 61 51 ff d6 } //00 00 
		$a_00_7 = {7e 15 00 } //00 31 
	condition:
		any of ($a_*)
 
}