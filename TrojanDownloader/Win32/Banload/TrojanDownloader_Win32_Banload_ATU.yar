
rule TrojanDownloader_Win32_Banload_ATU{
	meta:
		description = "TrojanDownloader:Win32/Banload.ATU,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {42 75 74 74 6f 6e 37 43 6c 69 63 6b } //02 00  Button7Click
		$a_01_1 = {43 50 6c 41 70 70 6c 65 74 } //03 00  CPlApplet
		$a_01_2 = {41 43 43 54 69 6d 65 72 } //03 00  ACCTimer
		$a_01_3 = {54 41 42 41 4a 41 52 41 } //03 00  TABAJARA
		$a_01_4 = {43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 5c 00 48 00 41 00 4c 00 39 00 54 00 48 00 2e 00 6c 00 6f 00 67 00 } //00 00  C:\Documents and Settings\Administrator\HAL9TH.log
		$a_00_5 = {5d 04 00 00 13 } //0d 03 
	condition:
		any of ($a_*)
 
}