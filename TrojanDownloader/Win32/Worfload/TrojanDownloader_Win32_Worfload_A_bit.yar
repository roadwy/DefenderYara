
rule TrojanDownloader_Win32_Worfload_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Worfload.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 04 00 00 64 00 "
		
	strings :
		$a_01_0 = {49 6e 6e 6f 20 53 65 74 75 70 20 4d 65 73 73 61 67 65 73 } //0a 00  Inno Setup Messages
		$a_01_1 = {6c 61 70 61 70 61 68 6f 73 74 65 72 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f 65 78 65 2f 41 64 73 53 68 6f 77 5f 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //0a 00  lapapahoster.com/download/exe/AdsShow_installer.exe
		$a_01_2 = {6e 69 68 61 6d 61 74 69 6f 74 6f 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f 65 78 65 2f 41 64 73 53 68 6f 77 5f 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //01 00  nihamatioto.com/download/exe/AdsShow_installer.exe
		$a_01_3 = {44 4f 57 4e 4c 4f 41 44 41 4e 44 45 58 45 43 55 54 45 } //00 00  DOWNLOADANDEXECUTE
	condition:
		any of ($a_*)
 
}