
rule TrojanDownloader_Win32_Sarhust_A{
	meta:
		description = "TrojanDownloader:Win32/Sarhust.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {48 00 41 00 52 00 44 00 57 00 41 00 52 00 45 00 5c 00 44 00 45 00 53 00 43 00 52 00 49 00 50 00 54 00 49 00 4f 00 4e 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 65 00 6e 00 74 00 72 00 61 00 6c 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 5c 00 30 00 } //1 HARDWARE\DESCRIPTION\System\CentralProcessor\0
		$a_01_1 = {77 00 6d 00 69 00 70 00 72 00 76 00 73 00 65 00 2e 00 69 00 6e 00 69 00 } //1 wmiprvse.ini
		$a_01_2 = {44 6f 6e 27 74 20 66 69 6e 64 20 63 6d 64 2e 65 78 65 2c 70 6c 65 61 73 65 20 63 68 65 63 6b 20 61 67 61 69 6e 20 6f 72 20 75 70 6c 6f 61 64 20 74 68 65 20 70 72 6f 67 72 61 6d 21 } //1 Don't find cmd.exe,please check again or upload the program!
		$a_01_3 = {4e 76 53 6d 61 72 74 4d 61 78 55 73 65 44 79 6e 61 6d 69 63 44 65 76 69 63 65 47 72 69 64 73 } //1 NvSmartMaxUseDynamicDeviceGrids
		$a_01_4 = {52 65 6e 49 6e 69 74 49 6e 73 74 61 6e 63 65 40 31 32 } //1 RenInitInstance@12
		$a_03_5 = {83 c4 0c 8d 8d 90 01 01 ff ff ff e8 90 01 04 8d 45 90 01 01 50 6a 00 8d 85 90 01 01 ff ff ff 50 68 90 01 04 6a 00 6a 00 ff 15 90 01 04 89 45 90 01 01 85 c0 74 90 00 } //1
		$a_03_6 = {55 8b ec 81 ec 90 01 04 e8 90 01 04 68 90 01 04 6a 00 e8 90 01 02 00 00 83 c4 08 68 90 01 02 00 00 ff 15 90 01 04 8d 8d 90 01 01 ff ff ff e8 90 01 02 00 00 8d 8d 90 01 01 ff ff ff e8 90 01 02 00 00 8d 8d 90 01 01 ff ff ff e8 90 01 02 00 00 6a 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1) >=5
 
}