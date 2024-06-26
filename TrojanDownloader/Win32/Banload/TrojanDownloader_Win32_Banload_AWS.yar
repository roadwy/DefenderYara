
rule TrojanDownloader_Win32_Banload_AWS{
	meta:
		description = "TrojanDownloader:Win32/Banload.AWS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 4d 49 43 52 4f 53 4f 46 54 5c 57 49 4e 44 4f 57 53 5c 43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e 00 } //01 00  䵜䍉佒体呆坜义佄南䍜剕䕒呎䕖卒佉屎啒N
		$a_03_1 = {73 65 6c 65 63 74 20 67 75 61 72 64 61 90 01 01 20 66 72 6f 6d 20 72 6f 70 65 69 72 6f 90 00 } //01 00 
		$a_03_2 = {63 00 65 00 3d 00 53 00 51 00 4c 00 90 01 08 2e 00 53 00 6d 00 61 00 72 00 74 00 65 00 72 00 61 00 73 00 70 00 2e 00 6e 00 65 00 90 02 10 5c 90 02 10 2e 65 78 65 90 00 } //00 00 
		$a_00_3 = {78 0b } //01 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Banload_AWS_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.AWS,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {5c 47 62 50 6c 90 02 10 75 67 69 6e 00 90 00 } //01 00 
		$a_01_1 = {70 72 6f 67 72 61 6d 66 69 6c 65 73 00 00 00 00 ff ff ff ff 01 00 00 00 5c 00 00 00 ff ff ff ff 01 00 00 00 47 00 00 00 ff ff ff ff 01 00 00 00 62 } //0a 00 
		$a_03_2 = {73 65 6c 65 63 74 20 64 61 64 6f 73 90 02 20 66 72 6f 6d 20 74 62 6c 5f 63 61 72 72 65 67 61 90 00 } //0a 00 
		$a_01_3 = {5c 4d 49 43 52 4f 53 4f 46 54 5c 57 49 4e 44 4f 57 53 5c 43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e 00 } //0a 00  䵜䍉佒体呆坜义佄南䍜剕䕒呎䕖卒佉屎啒N
		$a_03_4 = {63 00 65 00 3d 00 53 00 51 00 4c 00 35 00 30 00 30 00 90 04 01 02 35 39 00 2e 00 53 00 6d 00 61 00 72 00 74 00 65 00 72 00 61 00 73 00 70 00 2e 00 6e 00 65 00 90 00 } //0a 00 
		$a_01_5 = {53 00 6f 00 75 00 72 00 63 00 65 00 3d 00 31 00 38 00 34 00 2e 00 31 00 36 00 38 00 2e 00 31 00 39 00 34 00 2e 00 35 00 35 00 } //00 00  Source=184.168.194.55
		$a_00_6 = {87 10 00 00 79 27 d5 34 8d af 75 9a bc a1 39 bd ed 28 05 00 } //5d 04 
	condition:
		any of ($a_*)
 
}