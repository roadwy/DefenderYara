
rule Virus_Linux_Marker_KI{
	meta:
		description = "Virus:Linux/Marker.KI,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {4b 69 6c 6c 20 4f 70 74 69 6f 6e 73 2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 28 38 29 20 26 20 22 5c 2a 2e 64 6f 63 22 } //1 Kill Options.DefaultFilePath(8) & "\*.doc"
		$a_00_1 = {4b 69 6c 6c 20 4f 70 74 69 6f 6e 73 2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 28 38 29 20 26 20 22 5c 2a 2e 64 6f 74 22 } //1 Kill Options.DefaultFilePath(8) & "\*.dot"
		$a_00_2 = {4f 70 74 69 6f 6e 73 2e 56 69 72 75 73 50 72 6f 74 65 63 74 69 6f 6e 20 3d 20 46 61 6c 73 65 } //1 Options.VirusProtection = False
		$a_00_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 45 6e 61 62 6c 65 43 61 6e 63 65 6c 4b 65 79 20 3d 20 77 64 43 61 6e 63 65 6c 44 69 73 61 62 6c 65 64 } //1 Application.EnableCancelKey = wdCancelDisabled
		$a_00_4 = {49 66 20 28 53 79 73 74 65 6d 2e 50 72 69 76 61 74 65 50 72 6f 66 69 6c 65 53 74 72 69 6e 67 28 22 22 2c 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4d 53 20 53 65 74 75 70 20 28 41 43 4d 45 29 5c 55 73 65 72 20 49 6e 66 6f 22 2c 20 5f 22 4c 6f 67 44 61 74 61 20 69 6e 22 29 20 3d 20 46 61 6c 73 65 29 20 54 68 65 6e 20 47 6f 53 75 62 20 4c 6f 67 67 69 6e 67 49 6e 20 49 66 20 57 65 65 6b 64 61 79 28 4e 6f 77 28 29 29 20 3d 20 31 20 54 68 65 6e 20 47 6f 53 75 62 20 53 68 6f 77 4d 65 } //2 If (System.PrivateProfileString("", "HKEY_CURRENT_USER\Software\Microsoft\MS Setup (ACME)\User Info", _"LogData in") = False) Then GoSub LoggingIn If Weekday(Now()) = 1 Then GoSub ShowMe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*2) >=4
 
}