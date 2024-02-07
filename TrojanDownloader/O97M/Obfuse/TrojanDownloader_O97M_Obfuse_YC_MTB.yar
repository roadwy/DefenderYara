
rule TrojanDownloader_O97M_Obfuse_YC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.YC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {73 74 72 54 65 6d 70 20 3d 20 43 68 72 28 56 61 6c 28 22 26 48 22 20 2b 20 4d 69 64 28 68 65 78 74 6f 73 74 72 2c 20 90 02 03 20 32 29 29 29 90 00 } //01 00 
		$a_02_1 = {64 20 3d 20 43 75 72 46 6f 6c 64 65 72 20 2b 20 22 90 02 08 2e 64 6c 6c 90 00 } //01 00 
		$a_00_2 = {6f 62 6a 33 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 72 75 6e 64 6c 6c 33 32 } //01 00  obj3.ShellExecute "rundll32
		$a_00_3 = {47 65 74 4f 62 6a 65 63 74 28 43 68 72 57 28 31 31 30 29 20 2b 20 43 68 72 57 28 31 30 31 29 20 2b 20 43 68 72 57 28 31 31 39 29 20 2b 20 43 68 72 57 28 35 38 29 20 2b 20 43 68 72 57 28 34 39 29 20 2b 20 43 68 72 57 28 35 31 29 20 2b 20 43 68 72 57 28 35 35 29 } //00 00  GetObject(ChrW(110) + ChrW(101) + ChrW(119) + ChrW(58) + ChrW(49) + ChrW(51) + ChrW(55)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_YC_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.YC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {54 65 6a 45 6e 61 20 3d 20 44 69 72 28 22 43 3a 5c 61 61 61 5f 54 6f 75 63 68 4d 65 4e 6f 74 2e 74 78 74 22 29 } //01 00  TejEna = Dir("C:\aaa_TouchMeNot.txt")
		$a_00_1 = {47 65 74 4f 62 6a 65 63 74 28 53 74 72 52 65 76 65 72 73 65 28 22 73 73 22 20 2b 20 22 65 63 22 20 2b 20 22 6f 72 50 5f 22 20 2b 20 22 32 33 6e 22 20 2b 20 22 69 57 22 20 2b 20 22 3a 32 22 20 2b 20 22 76 6d 69 22 20 2b 20 22 63 5c 74 22 20 2b 20 22 6f 6f 72 3a 22 20 2b 20 22 73 74 6d 22 20 2b 20 22 67 6d 22 20 2b 20 22 6e 22 20 2b 20 22 69 77 22 29 29 } //01 00  GetObject(StrReverse("ss" + "ec" + "orP_" + "23n" + "iW" + ":2" + "vmi" + "c\t" + "oor:" + "stm" + "gm" + "n" + "iw"))
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 28 54 65 6d 70 43 29 } //01 00  Application.ExecuteExcel4Macro(TempC)
		$a_00_3 = {53 65 74 20 49 65 72 61 6a 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 22 29 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 69 6e 67 53 22 } //00 00  Set Ieraj = GetObject("winmgmts:").Get("Win32_PingS"
	condition:
		any of ($a_*)
 
}