
rule TrojanProxy_Win32_Wonknod_E{
	meta:
		description = "TrojanProxy:Win32/Wonknod.E,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {20 00 2f 00 c7 45 90 01 01 73 00 76 00 c7 90 01 02 63 00 00 00 90 00 } //0a 00 
		$a_03_1 = {53 68 65 6c c7 90 01 02 6c 45 78 65 c7 90 01 02 63 75 74 65 90 00 } //01 00 
		$a_00_2 = {5b 55 70 67 72 61 64 65 53 65 72 76 69 63 65 20 66 61 69 6c 65 64 5d } //01 00  [UpgradeService failed]
		$a_00_3 = {6c 61 6e 75 63 68 } //01 00  lanuch
		$a_00_4 = {4c 00 69 00 76 00 65 00 75 00 70 00 } //01 00  Liveup
		$a_00_5 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 5c 00 46 00 69 00 6c 00 65 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //00 00  SOFTWARE\Microsoft\Network\FileService
	condition:
		any of ($a_*)
 
}