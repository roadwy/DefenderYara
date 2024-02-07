
rule Trojan_BAT_Downloader_BA_MTB{
	meta:
		description = "Trojan:BAT/Downloader.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 49 6e 74 65 72 6e 61 6c 2e 53 68 65 6c 6c 43 6f 64 65 2e 45 64 69 74 6f 72 44 72 69 76 65 72 4c 69 76 65 2e 65 78 65 } //01 00  WindowsInternal.ShellCode.EditorDriverLive.exe
		$a_01_1 = {54 68 72 65 61 64 53 74 61 72 74 } //01 00  ThreadStart
		$a_01_2 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 } //01 00  GetTempFileName
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_4 = {47 65 74 54 65 6d 70 50 61 74 68 } //01 00  GetTempPath
		$a_01_5 = {47 65 74 50 61 74 68 52 6f 6f 74 } //01 00  GetPathRoot
		$a_01_6 = {24 62 38 34 63 31 33 35 62 2d 61 38 64 36 2d 34 37 31 36 2d 39 36 31 35 2d 35 61 66 30 39 36 32 65 62 32 38 37 } //00 00  $b84c135b-a8d6-4716-9615-5af0962eb287
	condition:
		any of ($a_*)
 
}