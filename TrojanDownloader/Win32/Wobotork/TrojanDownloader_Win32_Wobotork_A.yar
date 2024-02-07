
rule TrojanDownloader_Win32_Wobotork_A{
	meta:
		description = "TrojanDownloader:Win32/Wobotork.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 b9 0f 00 00 00 f7 f9 83 7d 90 01 01 10 8b 45 90 01 01 73 03 8d 45 90 01 01 8a 5c 10 01 8d 75 90 01 01 e8 90 01 04 4f 75 d8 90 00 } //01 00 
		$a_01_1 = {53 65 74 20 6f 53 68 65 6c 6c 20 3d 20 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 3a 6f 53 68 65 6c 6c 2e 45 78 65 63 28 } //00 00  Set oShell = WScript.CreateObject("WScript.Shell"):oShell.Exec(
	condition:
		any of ($a_*)
 
}