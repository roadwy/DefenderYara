
rule TrojanDownloader_BAT_Tiny_MA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 64 76 45 79 6b 57 69 6d } //01 00  https://pastebin.com/raw/dvEykWim
		$a_81_1 = {63 3a 5c 74 65 6d 70 5c 41 73 73 65 6d 62 6c 79 2e 65 78 65 } //01 00  c:\temp\Assembly.exe
		$a_81_2 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 4a 6f 68 6e 44 6f 65 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 74 6f 6f 6c 2e 65 78 65 } //01 00  C:\Documents and Settings\JohnDoe\Application Data\tool.exe
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_81_5 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_6 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_81_7 = {67 65 74 5f 4e 65 74 77 6f 72 6b } //01 00  get_Network
		$a_81_8 = {67 65 74 5f 55 73 65 72 } //01 00  get_User
		$a_81_9 = {44 3a 5c 43 6f 64 69 6e 67 47 75 79 20 42 61 63 6b 75 70 32 5c 72 65 70 6f 73 5c 44 52 4f 50 50 45 52 5c 44 52 4f 50 50 45 52 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 64 2e 70 64 62 } //00 00  D:\CodingGuy Backup2\repos\DROPPER\DROPPER\obj\Release\d.pdb
	condition:
		any of ($a_*)
 
}