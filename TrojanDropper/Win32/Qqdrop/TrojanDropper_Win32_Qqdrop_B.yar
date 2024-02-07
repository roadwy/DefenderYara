
rule TrojanDropper_Win32_Qqdrop_B{
	meta:
		description = "TrojanDropper:Win32/Qqdrop.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 6c 6c 20 55 73 65 72 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 54 65 6e 63 65 6e 74 5c 51 51 44 6f 77 6e 6c 6f 61 64 5c 51 51 2e 65 78 65 } //01 00  C:\Documents and Settings\All Users\Application Data\Tencent\QQDownload\QQ.exe
		$a_00_1 = {51 51 2e 48 4c 50 } //01 00  QQ.HLP
		$a_01_2 = {51 51 44 6f 77 6e 6c 6f 61 64 52 65 63 6f 72 64 50 61 74 68 } //01 00  QQDownloadRecordPath
		$a_00_3 = {51 51 2e 49 4e 49 } //01 00  QQ.INI
		$a_01_4 = {25 73 5c 25 73 2e 6c 6e 6b } //01 00  %s\%s.lnk
		$a_03_5 = {c6 44 24 0c 90 01 01 c6 44 24 0d 90 01 01 c6 44 24 0e 90 01 01 c6 44 24 0f 90 01 01 c6 44 24 10 90 01 01 c6 44 24 11 90 01 01 c6 44 24 12 90 01 01 c6 44 24 13 90 01 01 c6 44 24 14 90 01 01 c6 44 24 15 90 01 01 c6 44 24 16 90 01 01 c6 44 24 17 90 01 01 c6 44 24 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}