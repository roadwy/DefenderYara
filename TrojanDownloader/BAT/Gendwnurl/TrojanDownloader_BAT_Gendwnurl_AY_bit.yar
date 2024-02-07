
rule TrojanDownloader_BAT_Gendwnurl_AY_bit{
	meta:
		description = "TrojanDownloader:BAT/Gendwnurl.AY!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 00 73 00 68 00 53 00 68 00 65 00 6c 00 6c 00 2e 00 52 00 75 00 6e 00 20 00 22 00 63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 20 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 2f 00 70 00 72 00 69 00 6f 00 72 00 69 00 74 00 79 00 20 00 68 00 69 00 67 00 68 00 } //01 00  WshShell.Run "cmd /c bitsadmin /transfer /download /priority high
		$a_03_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 61 00 6e 00 61 00 67 00 65 00 31 00 6c 00 6e 00 6b 00 2e 00 70 00 77 00 90 02 30 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_01_2 = {73 00 74 00 61 00 72 00 74 00 20 00 57 00 45 00 73 00 63 00 72 00 2e 00 76 00 62 00 73 00 } //00 00  start WEscr.vbs
	condition:
		any of ($a_*)
 
}