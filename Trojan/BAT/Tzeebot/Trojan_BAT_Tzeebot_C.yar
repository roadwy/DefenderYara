
rule Trojan_BAT_Tzeebot_C{
	meta:
		description = "Trojan:BAT/Tzeebot.C,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 65 63 6b 46 69 6c 65 4d 44 35 } //01 00  CheckFileMD5
		$a_01_1 = {47 65 74 46 69 6c 65 } //01 00  GetFile
		$a_01_2 = {55 70 6c 6f 61 64 46 69 6c 65 } //01 00  UploadFile
		$a_01_3 = {50 72 6f 63 65 73 73 55 70 64 61 74 65 43 6f 6d 6d 61 6e 64 73 } //02 00  ProcessUpdateCommands
		$a_01_4 = {55 47 65 74 41 56 6c 69 73 74 } //02 00  UGetAVlist
		$a_01_5 = {67 65 74 53 68 61 64 79 50 72 6f 63 65 73 73 } //02 00  getShadyProcess
		$a_01_6 = {47 69 76 65 4d 61 64 75 6c 65 56 65 72 73 69 6f 6e } //05 00  GiveMaduleVersion
		$a_03_7 = {06 17 58 0a 90 0a 40 00 07 7e 90 01 02 00 04 7e 90 01 02 00 04 90 02 02 6f 90 01 02 00 0a 6f 90 01 02 00 0a 8c 90 01 01 00 00 01 28 90 01 01 00 00 0a 0b 90 00 } //0a 00 
		$a_01_8 = {41 6e 74 69 56 69 72 75 73 44 65 74 } //00 00  AntiVirusDet
		$a_00_9 = {5d 04 00 00 9d 27 03 80 5c 28 00 00 9e } //27 03 
	condition:
		any of ($a_*)
 
}