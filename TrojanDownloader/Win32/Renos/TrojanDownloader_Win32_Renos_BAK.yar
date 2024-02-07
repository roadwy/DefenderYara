
rule TrojanDownloader_Win32_Renos_BAK{
	meta:
		description = "TrojanDownloader:Win32/Renos.BAK,SIGNATURE_TYPE_PEHSTR_EXT,ffffffd2 07 ffffffd2 07 06 00 00 ffffffe8 03 "
		
	strings :
		$a_02_0 = {53 70 79 47 75 61 72 64 50 72 6f 90 02 10 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 90 00 } //e8 03 
		$a_00_1 = {53 65 74 74 69 6e 67 73 5c 55 73 65 72 20 41 67 65 6e 74 5c 50 6f 73 74 20 50 6c 61 74 66 6f 72 6d } //01 00  Settings\User Agent\Post Platform
		$a_00_2 = {57 69 6e 64 6f 77 73 20 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 20 68 61 73 20 64 65 74 65 63 74 65 64 20 61 20 53 70 79 77 61 72 65 20 69 6e 66 65 63 74 69 6f 6e 21 } //01 00  Windows Security Center has detected a Spyware infection!
		$a_00_3 = {49 6e 73 74 61 6c 6c 20 61 6e 74 69 2d 73 70 79 77 61 72 65 20 74 6f 20 70 72 65 76 65 6e 74 20 64 61 74 61 20 6c 6f 73 73 21 } //01 00  Install anti-spyware to prevent data loss!
		$a_00_4 = {43 6c 69 63 6b 20 68 65 72 65 20 74 6f 20 69 6e 73 74 61 6c 6c 20 6c 61 74 65 73 74 20 61 6e 74 69 73 70 79 77 61 72 65 20 74 6f 6f 6c 2e } //01 00  Click here to install latest antispyware tool.
		$a_01_5 = {41 44 30 33 31 } //00 00  AD031
	condition:
		any of ($a_*)
 
}