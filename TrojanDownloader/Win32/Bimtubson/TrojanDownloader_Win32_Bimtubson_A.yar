
rule TrojanDownloader_Win32_Bimtubson_A{
	meta:
		description = "TrojanDownloader:Win32/Bimtubson.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 6c 6f 67 2f 76 65 72 2e 61 73 70 3f 49 44 3d 30 } //01 00  /log/ver.asp?ID=0
		$a_01_1 = {52 65 66 72 65 73 68 22 20 43 4f 4e 54 45 4e 54 3d 22 30 3b 20 55 52 4c 3d 25 30 3a 73 22 3e } //01 00  Refresh" CONTENT="0; URL=%0:s">
		$a_01_2 = {26 26 26 26 26 26 73 69 64 26 72 75 6e 65 26 74 2e 74 69 26 26 26 64 26 26 } //01 00  &&&&&&sid&rune&t.ti&&&d&&
		$a_01_3 = {8a 10 80 ea 0a 74 05 80 ea 03 75 03 c6 00 00 40 4b 75 ed } //00 00 
	condition:
		any of ($a_*)
 
}