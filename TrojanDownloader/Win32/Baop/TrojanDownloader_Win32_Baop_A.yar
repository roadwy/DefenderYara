
rule TrojanDownloader_Win32_Baop_A{
	meta:
		description = "TrojanDownloader:Win32/Baop.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0a 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 65 62 42 61 6e 62 65 6e 5f 4f 6e 52 65 61 64 79 53 74 61 74 65 43 68 61 6e 67 65 } //01 00  WebBanben_OnReadyStateChange
		$a_00_1 = {6f 00 66 00 74 00 2f 00 75 00 70 00 6c 00 69 00 73 00 74 00 2e 00 61 00 73 00 70 00 78 00 3f 00 61 00 64 00 6d 00 69 00 6e 00 3d 00 } //01 00  oft/uplist.aspx?admin=
		$a_00_2 = {2f 00 64 00 62 00 2f 00 62 00 61 00 6e 00 62 00 65 00 6e 00 2e 00 78 00 6d 00 6c 00 } //01 00  /db/banben.xml
		$a_00_3 = {2f 00 64 00 62 00 2f 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 78 00 6d 00 6c 00 } //01 00  /db/config.xml
		$a_00_4 = {2f 00 75 00 70 00 74 00 6d 00 70 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //05 00  /uptmp/update.exe
		$a_03_5 = {70 00 61 00 74 00 68 00 3d 00 00 00 90 02 10 26 00 73 00 74 00 61 00 72 00 74 00 3d 00 00 00 90 00 } //05 00 
		$a_00_6 = {6f 00 66 00 74 00 2f 00 64 00 6f 00 77 00 6e 00 2e 00 61 00 73 00 70 00 78 00 } //00 00  oft/down.aspx
	condition:
		any of ($a_*)
 
}