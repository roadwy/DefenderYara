
rule TrojanDownloader_Linux_Bartallex{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {61 48 52 30 63 44 6f 76 4c 33 56 74 61 57 4e 76 62 6e 52 79 62 32 77 75 59 32 39 74 4c 6d 4a 79 4c 32 52 76 59 33 4d 76 90 01 05 53 35 6c 65 47 55 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_2{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 6c 69 76 65 73 65 63 6f 6e 64 63 68 61 6e 63 65 2e 70 72 65 73 73 2f 73 79 73 2f 63 31 36 30 38 65 63 38 37 35 32 37 33 64 36 30 33 34 36 64 64 37 37 36 30 32 65 35 30 64 33 30 32 33 65 39 61 2e 65 78 65 } //00 00  /livesecondchance.press/sys/c1608ec875273d60346dd77602e50d3023e9a.exe
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_3{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //01 00  Sub AutoOpen()
		$a_01_1 = {26 20 22 2e 22 20 26 20 22 65 22 20 26 20 22 78 22 20 26 20 22 65 22 } //01 00  & "." & "e" & "x" & "e"
		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 61 22 20 26 20 22 70 22 20 26 20 22 70 22 20 26 20 22 64 22 20 26 20 22 61 22 20 26 20 22 74 22 20 26 20 22 61 22 29 20 26 } //00 00  = Environ("a" & "p" & "p" & "d" & "a" & "t" & "a") &
		$a_00_3 = {8f 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_4{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 04 00 "
		
	strings :
		$a_01_0 = {62 6c 75 65 66 69 6c 65 2e 62 69 7a 2f 64 6f 77 6e 6c 6f 61 64 73 2f 65 38 32 30 31 30 35 64 62 39 36 30 65 36 35 62 37 63 64 37 65 38 65 36 35 65 33 65 32 66 32 35 31 37 39 38 31 34 34 2e 65 78 65 } //01 00  bluefile.biz/downloads/e820105db960e65b7cd7e8e65e3e2f251798144.exe
		$a_01_1 = {79 28 22 61 74 61 44 70 70 41 22 } //01 00  y("ataDppA"
		$a_01_2 = {22 50 4d 45 54 22 } //01 00  "PMET"
		$a_01_3 = {22 2e 65 78 65 22 } //00 00  ".exe"
		$a_00_4 = {8f 77 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_5{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 57 56 46 38 43 7a 36 48 28 29 } //01 00  uWVF8Cz6H()
		$a_01_1 = {54 6f 6d 6a 78 4a 39 47 44 58 31 68 72 7a 2e 4f 70 65 6e 20 55 73 65 72 46 6f 72 6d 32 2e 54 65 78 74 42 6f 78 37 } //01 00  TomjxJ9GDX1hrz.Open UserForm2.TextBox7
		$a_01_2 = {57 4c 34 4a 6f 38 45 78 77 36 37 76 41 44 2e 48 77 4f 43 78 35 31 63 41 7a 34 71 2c 20 32 } //01 00  WL4Jo8Exw67vAD.HwOCx51cAz4q, 2
		$a_01_3 = {2e 78 6a 53 54 64 76 50 76 6f 4d 63 57 4d 69 } //00 00  .xjSTdvPvoMcWMi
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_6{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 54 54 48 20 3d 20 22 68 74 74 70 22 20 26 20 22 3a 2f 2f 22 } //01 00  ATTH = "http" & "://"
		$a_01_1 = {42 51 48 4a 44 51 20 3d 20 22 73 61 22 20 2b 20 22 76 65 70 22 20 2b 20 22 69 63 22 20 26 20 43 68 72 28 34 36 29 20 26 20 22 73 75 22 20 2b 20 48 55 51 44 } //01 00  BQHJDQ = "sa" + "vep" + "ic" & Chr(46) & "su" + HUQD
		$a_01_2 = {54 53 54 53 20 3d 20 22 2e 22 20 2b 20 22 74 78 22 20 2b 20 22 74 22 } //01 00  TSTS = "." + "tx" + "t"
		$a_01_3 = {47 4e 47 20 3d 20 22 2e 6a 22 20 26 20 22 70 67 22 } //00 00  GNG = ".j" & "pg"
		$a_00_4 = {8f 9e } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_7{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 54 54 48 20 3d 20 22 68 74 22 20 26 20 22 74 22 20 26 20 22 22 20 26 20 22 70 22 20 26 20 22 3a 22 20 26 20 22 2f 22 20 26 20 43 68 72 28 34 37 29 } //01 00  ATTH = "ht" & "t" & "" & "p" & ":" & "/" & Chr(47)
		$a_01_1 = {53 58 45 20 3d 20 53 58 45 45 20 26 20 53 58 41 41 20 26 20 22 22 20 26 20 22 78 65 22 } //01 00  SXE = SXEE & SXAA & "" & "xe"
		$a_01_2 = {47 4e 47 20 3d 20 43 68 72 28 32 20 5e 20 32 20 2b 20 34 32 29 20 2b 20 22 6a 70 67 22 } //01 00  GNG = Chr(2 ^ 2 + 42) + "jpg"
		$a_01_3 = {54 53 54 53 20 3d 20 22 2e 22 20 2b 20 22 74 22 20 2b 20 22 78 74 22 } //00 00  TSTS = "." + "t" + "xt"
		$a_00_4 = {8f a8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_8{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 68 22 20 2b 20 69 75 79 79 20 2b 20 22 70 3a 22 20 2b 20 62 62 76 43 43 43 20 2b 20 22 73 74 65 62 22 20 2b 20 6f 6f 6f 69 64 73 66 20 2b 20 22 6d 2f 22 20 2b 20 79 79 79 79 73 79 73 79 20 2b 20 22 68 70 3f 69 3d 22 } //01 00  "h" + iuyy + "p:" + bbvCCC + "steb" + oooidsf + "m/" + yyyysysy + "hp?i="
		$a_01_1 = {26 20 22 5c 6d 4e 73 64 65 77 65 65 2e 76 62 73 22 } //01 00  & "\mNsdewee.vbs"
		$a_01_2 = {43 68 72 24 28 31 30 35 29 20 26 20 43 68 72 24 28 31 31 30 29 20 26 20 43 68 72 24 28 34 36 29 20 26 20 43 68 72 24 28 39 39 29 20 26 20 43 68 72 24 28 31 31 31 29 } //00 00  Chr$(105) & Chr$(110) & Chr$(46) & Chr$(99) & Chr$(111)
		$a_00_3 = {8f } //b3 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_9{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {22 74 68 75 79 64 75 6f 6e 67 73 70 61 2e 63 22 20 26 20 22 6f 6d 2f } //03 00  "thuyduongspa.c" & "om/
		$a_01_1 = {22 74 68 65 74 75 6e 61 73 6c 61 62 2e 63 22 20 26 20 22 6f 6d 2f } //01 00  "thetunaslab.c" & "om/
		$a_01_2 = {70 2d 61 64 6d 69 6e 2f 63 73 73 2f 63 6f 6c 6f 72 73 2f 6d 69 64 6e 69 67 68 74 2f } //01 00  p-admin/css/colors/midnight/
		$a_01_3 = {77 22 20 26 20 22 70 2d 73 6e 61 70 73 68 6f 74 73 2f 22 } //01 00  w" & "p-snapshots/"
		$a_01_4 = {41 54 54 48 20 3d 20 41 54 54 48 20 2b 20 22 3a 2f 2f 22 } //01 00  ATTH = ATTH + "://"
		$a_01_5 = {22 54 65 22 20 2b 20 22 6d 70 22 } //01 00  "Te" + "mp"
		$a_01_6 = {28 41 54 54 48 20 2b 20 53 54 54 31 20 2b 20 4c 4e 53 53 29 } //00 00  (ATTH + STT1 + LNSS)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_10{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 07 00 00 04 00 "
		
	strings :
		$a_01_0 = {77 2e 6d 61 69 72 69 65 73 61 69 6e 74 67 65 72 76 61 69 73 33 33 2e 66 72 2f 74 6d 70 2f 36 37 31 35 33 31 37 38 2e 74 78 74 22 } //04 00  w.mairiesaintgervais33.fr/tmp/67153178.txt"
		$a_01_1 = {73 75 70 72 65 6d 6f 2e 6f 72 67 2e 62 72 2f 74 6d 70 2f 36 37 31 35 33 31 37 38 2e 74 78 74 } //04 00  supremo.org.br/tmp/67153178.txt
		$a_01_2 = {77 77 2e 6d 61 69 72 69 65 73 61 69 6e 74 67 65 72 76 61 69 73 33 33 2e 66 72 2f 74 6d 70 2f 36 37 31 35 33 31 37 38 2e 74 78 74 22 } //01 00  ww.mairiesaintgervais33.fr/tmp/67153178.txt"
		$a_01_3 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //01 00  Sub Auto_Open()
		$a_01_4 = {4d 6f 64 75 6c 65 31 2e 42 61 64 28 } //01 00  Module1.Bad(
		$a_01_5 = {22 22 20 26 20 22 73 61 76 22 20 26 20 22 65 70 69 63 2e 73 75 2f 22 } //01 00  "" & "sav" & "epic.su/"
		$a_01_6 = {3d 20 22 6d 22 20 26 20 22 6f 64 75 6c 65 22 } //00 00  = "m" & "odule"
		$a_00_7 = {8f e0 00 00 } //04 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_11{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {20 3d 20 53 74 72 52 65 76 65 72 73 65 28 22 74 22 29 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 70 74 22 29 } //01 00   = StrReverse("t") + StrReverse("pt")
		$a_00_1 = {20 3d 20 53 74 72 52 65 76 65 72 73 65 28 22 2f 2f 3a 22 29 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 73 61 70 22 29 } //01 00   = StrReverse("//:") + StrReverse("sap")
		$a_00_2 = {20 3d 20 53 74 72 52 65 76 65 72 73 65 28 22 69 62 22 29 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 6f 63 2e 6e 22 29 } //01 00   = StrReverse("ib") + StrReverse("oc.n")
		$a_00_3 = {20 3d 20 53 74 72 52 65 76 65 72 73 65 28 22 6e 22 29 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 61 6f 6c 22 29 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 68 70 2e 64 22 29 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 3d 69 3f 70 22 29 } //00 00   = StrReverse("n") + StrReverse("aol") + StrReverse("hp.d") + StrReverse("=i?p")
		$a_00_4 = {8f f2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_12{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 06 00 00 04 00 "
		
	strings :
		$a_01_0 = {57 68 69 73 6b 79 42 61 72 20 4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 } //02 00  WhiskyBar Lib "urlmon" Alias "URLDownloadToFileA"
		$a_01_1 = {74 6d 70 20 3d 20 74 6d 70 20 26 20 43 68 72 28 41 73 63 28 78 29 20 2d 20 31 29 } //02 00  tmp = tmp & Chr(Asc(x) - 1)
		$a_01_2 = {57 68 69 73 6b 79 42 61 72 28 30 2c 20 43 68 65 63 6b 4e 75 6d 62 65 72 73 } //01 00  WhiskyBar(0, CheckNumbers
		$a_01_3 = {4e 65 77 50 61 74 68 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 22 } //01 00  NewPath = "C:\Users\Public\Documents"
		$a_01_4 = {53 70 6c 69 74 28 4c 6f 74 73 6f 66 46 75 63 6b 69 6e 67 53 74 72 69 6e 67 69 6e 61 6c 6c 69 6e 4f 6e 65 29 28 34 29 } //01 00  Split(LotsofFuckingStringinallinOne)(4)
		$a_01_5 = {28 41 6e 6f 74 68 65 72 53 68 69 74 69 73 48 65 72 65 53 61 79 73 74 68 69 73 29 28 34 29 } //00 00  (AnotherShitisHereSaysthis)(4)
		$a_00_6 = {8f 04 } //01 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_13{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 24 28 31 31 35 29 20 26 20 43 68 72 57 24 28 31 31 36 29 20 26 20 43 68 72 57 24 28 39 37 29 20 26 20 43 68 72 57 24 28 31 31 34 29 20 26 20 43 68 72 57 24 28 31 31 36 29 20 26 20 43 68 72 57 24 28 33 32 29 20 26 20 43 68 72 57 24 28 33 37 29 20 26 20 43 68 72 57 24 28 38 34 29 20 26 20 43 68 72 57 24 28 37 37 29 20 26 20 43 68 72 57 24 28 38 30 29 20 26 20 43 68 72 57 24 28 33 37 29 20 26 20 43 68 72 57 24 28 34 37 29 20 26 20 43 68 72 57 24 28 39 37 29 20 26 20 43 68 72 57 24 28 39 38 29 20 26 20 43 68 72 57 24 28 31 31 35 29 20 26 20 43 68 72 57 24 28 35 30 29 20 26 20 43 68 72 57 24 28 35 30 29 20 26 20 43 68 72 57 24 28 34 36 29 20 26 20 43 68 72 57 24 28 31 30 31 29 20 2b 20 22 78 65 22 2c 20 76 62 48 69 64 65 29 } //00 00  ChrW$(115) & ChrW$(116) & ChrW$(97) & ChrW$(114) & ChrW$(116) & ChrW$(32) & ChrW$(37) & ChrW$(84) & ChrW$(77) & ChrW$(80) & ChrW$(37) & ChrW$(47) & ChrW$(97) & ChrW$(98) & ChrW$(115) & ChrW$(50) & ChrW$(50) & ChrW$(46) & ChrW$(101) + "xe", vbHide)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_14{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 67 6a 36 37 76 66 66 73 64 67 3a 20 53 65 74 20 62 67 6a 36 37 76 66 66 73 64 67 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 33 2e 54 65 78 74 29 } //01 00  bgj67vffsdg: Set bgj67vffsdg = CreateObject(UserForm1.TextBox3.Text)
		$a_03_1 = {63 6d 64 73 20 3d 20 57 73 68 53 68 65 6c 6c 2e 52 75 6e 28 90 02 10 2c 20 30 2c 20 54 72 75 65 29 90 00 } //01 00 
		$a_01_2 = {2e 4f 70 65 6e 20 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 32 2e 54 65 78 74 2c 20 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 2e 54 65 78 74 2c 20 46 61 6c 73 65 } //02 00  .Open UserForm1.TextBox2.Text, UserForm1.TextBox1.Text, False
		$a_01_3 = {53 68 65 6c 6c 20 4d 6f 64 75 6c 65 31 2e 66 78 70 73 66 74 66 61 72 61 6b 71 68 28 63 61 6c 6c 72 65 74 75 72 6e 28 29 29 2c 20 30 } //02 00  Shell Module1.fxpsftfarakqh(callreturn()), 0
		$a_01_4 = {76 49 73 69 6a 4e 6e 45 20 3d 20 53 68 65 6c 6c 28 73 7a 6c 71 56 78 63 4b 28 6a 31 41 75 4e 29 2c 20 73 44 70 39 57 79 33 29 } //00 00  vIsijNnE = Shell(szlqVxcK(j1AuN), sDp9Wy3)
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_15{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 72 20 3d 20 53 74 72 20 2b 20 22 41 43 30 41 59 41 42 55 41 48 73 41 57 67 42 57 41 48 51 41 63 77 42 36 41 44 73 41 4a 77 41 37 41 43 51 41 61 51 41 39 41 44 41 41 4f 77 42 62 41 47 22 } //01 00  Str = Str + "AC0AYABUAHsAWgBWAHQAcwB6ADsAJwA7ACQAaQA9ADAAOwBbAG"
		$a_01_1 = {2b 20 22 4d 41 53 41 42 68 41 48 49 41 57 77 42 64 41 46 30 41 4a 41 42 43 41 44 30 41 4b 41 42 62 41 45 4d 41 53 41 42 68 41 48 49 41 57 77 42 64 41 46 30 41 22 } //01 00  + "MASABhAHIAWwBdAF0AJABCAD0AKABbAEMASABhAHIAWwBdAF0A"
		$a_01_2 = {2b 20 22 4b 41 41 6b 41 46 63 41 51 77 41 75 41 45 51 41 54 77 42 58 41 47 34 41 62 41 42 50 41 45 45 41 52 41 42 54 41 48 51 41 63 67 42 4a 41 47 34 41 5a 77 22 } //01 00  + "KAAkAFcAQwAuAEQATwBXAG4AbABPAEEARABTAHQAcgBJAG4AZw"
		$a_01_3 = {2b 20 22 41 6f 41 43 49 41 61 41 42 30 41 48 51 41 63 41 41 36 41 43 38 41 4c 77 41 31 41 44 49 41 4c 67 41 7a 41 44 59 41 4c 67 41 79 41 44 51 41 4e 51 41 75 22 } //01 00  + "AoACIAaAB0AHQAcAA6AC8ALwA1ADIALgAzADYALgAyADQANQAu"
		$a_01_4 = {2b 20 22 41 44 45 41 4e 41 41 31 41 44 6f 41 4f 41 41 77 41 44 67 41 4d 41 41 76 41 47 6b 41 62 67 42 6b 41 47 55 41 65 41 41 75 41 47 45 41 63 77 42 77 41 43 22 } //01 00  + "ADEANAA1ADoAOAAwADgAMAAvAGkAbgBkAGUAeAAuAGEAcwBwAC"
		$a_01_5 = {2b 20 22 49 41 4b 51 41 70 41 43 6b 41 66 41 41 6c 41 48 73 41 4a 41 42 66 41 43 30 41 59 67 42 59 41 45 38 41 63 67 41 6b 41 47 73 41 57 77 41 6b 41 45 6b 41 22 } //01 00  + "IAKQApACkAfAAlAHsAJABfAC0AYgBYAE8AcgAkAGsAWwAkAEkA"
		$a_01_6 = {2b 20 22 22 4b 77 41 72 41 43 55 41 4a 41 42 72 41 43 34 41 54 41 42 6c 41 47 34 41 5a 77 42 30 41 45 67 41 58 51 42 39 41 44 73 41 53 51 42 46 41 46 67 41 49 41 } //00 00  + ""KwArACUAJABrAC4ATABlAG4AZwB0AEgAXQB9ADsASQBFAFgAIA
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_16{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 72 28 39 39 29 20 26 20 43 68 72 28 31 30 34 29 20 26 20 22 6c 22 20 26 20 22 6f 22 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 31 30 30 29 20 26 20 22 65 22 20 26 20 43 68 72 28 31 31 35 29 20 26 20 22 69 22 20 26 20 22 67 22 20 26 20 22 6e 22 20 26 20 22 3b 22 20 26 20 43 68 72 28 34 36 29 20 26 20 43 68 72 28 31 30 32 29 20 26 20 43 68 72 28 31 31 34 29 20 26 20 43 68 72 28 34 37 29 20 26 20 43 68 72 28 35 31 29 20 26 20 43 68 72 28 35 32 29 20 26 20 43 68 72 28 35 33 29 20 26 20 43 68 72 28 34 37 29 } //01 00  Chr(99) & Chr(104) & "l" & "o" & Chr(101) & Chr(100) & "e" & Chr(115) & "i" & "g" & "n" & ";" & Chr(46) & Chr(102) & Chr(114) & Chr(47) & Chr(51) & Chr(52) & Chr(53) & Chr(47)
		$a_01_1 = {22 77 22 20 26 20 43 68 72 28 31 31 34 29 20 26 20 22 77 22 20 26 20 43 68 72 28 34 36 29 20 26 20 43 68 72 28 36 31 29 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 36 30 29 20 26 20 43 68 72 28 31 32 30 29 20 26 20 43 68 72 28 31 30 31 29 } //01 00  "w" & Chr(114) & "w" & Chr(46) & Chr(61) & Chr(101) & Chr(60) & Chr(120) & Chr(101)
		$a_01_2 = {43 68 72 28 38 37 29 20 26 20 22 3c 22 20 26 20 22 53 22 20 26 20 43 68 72 28 39 39 29 20 26 20 43 68 72 28 36 31 29 20 26 20 43 68 72 28 31 31 34 29 20 26 20 22 69 22 20 26 20 43 68 72 28 31 31 32 29 20 26 20 22 74 22 20 26 20 22 3b 22 20 26 20 43 68 72 28 34 36 29 20 26 20 43 68 72 28 38 33 29 20 26 20 43 68 72 28 36 31 29 20 26 20 22 68 22 20 26 20 43 68 72 28 31 30 31 29 20 26 20 22 3c 22 20 26 20 43 68 72 28 31 30 38 29 20 26 20 22 6c 22 } //00 00  Chr(87) & "<" & "S" & Chr(99) & Chr(61) & Chr(114) & "i" & Chr(112) & "t" & ";" & Chr(46) & Chr(83) & Chr(61) & "h" & Chr(101) & "<" & Chr(108) & "l"
	condition:
		any of ($a_*)
 
}