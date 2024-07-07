
rule TrojanDownloader_O97M_TrickBot_BK_MTB{
	meta:
		description = "TrojanDownloader:O97M/TrickBot.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 50 61 74 74 65 72 6e 20 3d 20 22 42 7c 6a 7c 76 7c 44 7c 71 7c 50 7c 58 7c 4d 7c 7a 7c 4c 7c 55 7c 5a 7c 46 7c 77 7c 56 7c 4e 7c 51 7c 4b 7c 49 7c 47 7c 48 7c 59 22 } //1 .Pattern = "B|j|v|D|q|P|X|M|z|L|U|Z|F|w|V|N|Q|K|I|G|H|Y"
		$a_01_1 = {50 75 47 76 56 20 3d 20 77 75 62 48 35 6f 2e 52 65 70 6c 61 63 65 28 4b 66 30 56 34 49 34 37 36 28 30 29 2c 20 22 22 29 } //1 PuGvV = wubH5o.Replace(Kf0V4I476(0), "")
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 56 42 53 63 72 69 70 74 2e 52 65 67 45 78 70 22 29 } //1 = CreateObject("VBScript.RegExp")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_TrickBot_BK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/TrickBot.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 28 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 48 69 67 68 53 63 6f 72 65 73 2e 62 61 74 22 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 } //1 Open ("c:\programdata\HighScores.bat") For Output As
		$a_01_1 = {50 72 69 6e 74 20 23 6a 2c 20 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e 20 2b 20 53 74 72 69 6e 67 28 32 37 2c 20 55 43 61 73 65 28 22 61 22 29 29 } //1 Print #j, Form1.Label1.Caption + String(27, UCase("a"))
		$a_01_2 = {57 69 6e 45 78 65 63 20 22 63 6d 64 20 2f 63 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 48 69 67 68 53 63 6f 72 65 73 2e 62 61 74 22 2c 20 30 } //1 WinExec "cmd /c c:\programdata\HighScores.bat", 0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_TrickBot_BK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/TrickBot.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 22 43 3a 5c 41 72 74 72 69 74 65 5c 53 61 72 69 6c 75 6d 61 62 53 41 52 31 35 33 31 39 31 2e 76 62 65 22 20 46 6f 72 20 4f 75 74 70 75 74 20 41 63 63 65 73 73 20 57 72 69 74 65 20 41 73 20 23 61 6e 61 6b 69 6e 75 6d 61 62 } //1 Open "C:\Artrite\SarilumabSAR153191.vbe" For Output Access Write As #anakinumab
		$a_01_1 = {6c 75 69 6e 70 65 64 72 6e 61 73 73 2e 43 61 70 74 69 6f 6e 20 3d 20 22 48 41 50 50 59 20 48 41 4c 4c 4f 57 45 45 4e 20 60 76 60 20 6f 6f 30 30 6f 6f 6f 6f 4f 4f 4f 6f 6f 6f 6f 6f 30 6f 6f 30 30 30 4f 4f 6f 6f 6f 6f 30 30 6f 6f 4f 4f 6f 6f 6f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 6f 6f 6f 6f 30 30 4f 4f 6f 6f 6f 6f 6f 6f 4f 4f 4f 4f 4f 22 } //1 luinpedrnass.Caption = "HAPPY HALLOWEEN `v` oo00ooooOOOooooo0oo000OOoooo00ooOOoooOOOOOOOOOOOOOOOOOOoooo00OOooooooOOOOO"
		$a_01_2 = {4d 73 67 42 6f 78 20 28 22 54 48 49 53 20 49 53 20 4a 41 53 4f 4e 21 20 48 41 50 50 59 20 48 41 4c 4c 4f 57 45 45 4e 21 20 4d 57 41 20 48 41 48 41 48 41 48 41 48 41 48 41 48 41 48 41 48 41 21 21 22 29 2c 20 76 62 45 78 63 6c 61 6d 61 74 69 6f 6e 2c 20 22 48 41 50 50 59 20 48 41 4c 4c 4f 57 45 45 4e 22 } //1 MsgBox ("THIS IS JASON! HAPPY HALLOWEEN! MWA HAHAHAHAHAHAHAHAHA!!"), vbExclamation, "HAPPY HALLOWEEN"
		$a_01_3 = {6c 75 69 6e 70 65 64 72 6e 61 73 73 2e 53 74 61 74 69 63 50 6c 61 6e 48 65 61 64 65 72 2e 43 61 70 74 69 6f 6e 20 3d 20 22 41 6e 64 20 77 68 65 6e 20 79 6f 75 27 72 65 20 64 6f 77 6e 20 68 65 72 65 20 77 69 74 68 20 6d 65 22 } //1 luinpedrnass.StaticPlanHeader.Caption = "And when you're down here with me"
		$a_01_4 = {44 65 6c 69 71 75 65 6e 74 42 72 65 61 6b 2e 44 44 45 49 6e 69 74 69 61 74 65 20 22 63 6d 64 22 2c 20 22 2f 63 20 43 3a 5c 41 72 74 72 69 74 65 5c 53 61 72 69 6c 75 6d 61 62 53 41 52 31 35 33 31 39 31 2e 76 62 65 22 } //1 DeliquentBreak.DDEInitiate "cmd", "/c C:\Artrite\SarilumabSAR153191.vbe"
		$a_01_5 = {6c 75 69 6e 70 65 64 72 6e 61 73 73 2e 56 53 50 46 2e 43 61 70 74 69 6f 6e 20 3d 20 22 41 6c 74 65 72 6e 61 74 65 20 50 6c 61 6e 20 66 6f 72 20 22 20 2b 20 53 74 61 74 65 73 56 61 72 20 2b 20 22 20 77 69 74 68 20 53 6e 69 70 22 } //1 luinpedrnass.VSPF.Caption = "Alternate Plan for " + StatesVar + " with Snip"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_TrickBot_BK_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/TrickBot.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 22 43 3a 5c 41 72 74 72 69 74 65 5c 53 61 72 69 6c 75 6d 61 62 53 41 52 31 35 33 31 39 31 2e 76 62 65 22 20 46 6f 72 20 4f 75 74 70 75 74 20 41 63 63 65 73 73 20 57 72 69 74 65 20 41 73 20 23 61 6e 61 6b 69 6e 75 6d 61 62 } //1 Open "C:\Artrite\SarilumabSAR153191.vbe" For Output Access Write As #anakinumab
		$a_01_1 = {6c 75 69 6e 70 65 64 72 6e 61 73 73 2e 43 61 70 74 69 6f 6e 20 3d 20 22 48 41 50 50 59 20 48 41 4c 4c 4f 57 45 45 4e 20 60 76 60 20 6f 6f 30 30 6f 6f 6f 6f 4f 4f 4f 6f 6f 6f 6f 6f 30 6f 6f 30 30 30 4f 4f 6f 6f 6f 6f 30 30 6f 6f 4f 4f 6f 6f 6f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 4f 6f 6f 6f 6f 30 30 4f 4f 6f 6f 6f 6f 6f 6f 4f 4f 4f 4f 4f 22 } //1 luinpedrnass.Caption = "HAPPY HALLOWEEN `v` oo00ooooOOOooooo0oo000OOoooo00ooOOoooOOOOOOOOOOOOOOOOOOoooo00OOooooooOOOOO"
		$a_01_2 = {4d 73 67 42 6f 78 20 28 22 54 48 49 53 20 49 53 20 4a 41 53 4f 4e 21 20 48 41 50 50 59 20 48 41 4c 4c 4f 57 45 45 4e 21 20 4d 57 41 20 48 41 48 41 48 41 48 41 48 41 48 41 48 41 48 41 48 41 21 21 22 29 2c 20 76 62 45 78 63 6c 61 6d 61 74 69 6f 6e 2c 20 22 48 41 50 50 59 20 48 41 4c 4c 4f 57 45 45 4e 22 } //1 MsgBox ("THIS IS JASON! HAPPY HALLOWEEN! MWA HAHAHAHAHAHAHAHAHA!!"), vbExclamation, "HAPPY HALLOWEEN"
		$a_01_3 = {6c 75 69 6e 70 65 64 72 6e 61 73 73 2e 53 74 61 74 69 63 50 6c 61 6e 48 65 61 64 65 72 2e 43 61 70 74 69 6f 6e 20 3d 20 22 41 6e 64 20 77 68 65 6e 20 79 6f 75 27 72 65 20 64 6f 77 6e 20 68 65 72 65 20 77 69 74 68 20 6d 65 22 } //1 luinpedrnass.StaticPlanHeader.Caption = "And when you're down here with me"
		$a_01_4 = {44 65 6c 69 71 75 65 6e 74 42 72 65 61 6b 2e 44 44 45 49 6e 69 74 69 61 74 65 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 22 2c 20 22 43 3a 5c 41 72 74 72 69 74 65 5c 53 61 72 69 6c 75 6d 61 62 53 41 52 31 35 33 31 39 31 2e 76 62 65 22 } //1 DeliquentBreak.DDEInitiate "explorer.exe", "C:\Artrite\SarilumabSAR153191.vbe"
		$a_01_5 = {6c 75 69 6e 70 65 64 72 6e 61 73 73 2e 56 53 50 46 2e 43 61 70 74 69 6f 6e 20 3d 20 22 41 6c 74 65 72 6e 61 74 65 20 50 6c 61 6e 20 66 6f 72 20 22 20 2b 20 53 74 61 74 65 73 56 61 72 20 2b 20 22 20 77 69 74 68 20 53 6e 69 70 22 } //1 luinpedrnass.VSPF.Caption = "Alternate Plan for " + StatesVar + " with Snip"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}