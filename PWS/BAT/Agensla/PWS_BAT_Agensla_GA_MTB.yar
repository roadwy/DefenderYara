
rule PWS_BAT_Agensla_GA_MTB{
	meta:
		description = "PWS:BAT/Agensla.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,26 00 26 00 0f 00 00 "
		
	strings :
		$a_80_0 = {2f 63 20 6e 65 74 73 68 20 77 6c 61 6e 20 73 68 6f 77 20 70 72 6f 66 69 6c 65 73 } ///c netsh wlan show profiles  10
		$a_80_1 = {6b 65 79 3d 63 6c 65 61 72 } //key=clear  10
		$a_80_2 = {57 69 66 69 20 4e 61 6d 65 } //Wifi Name  10
		$a_80_3 = {68 74 74 70 3a 2f 2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //http://api.telegram.org/bot  1
		$a_80_4 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //DisableTaskMgr  1
		$a_80_5 = {30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d 2f 75 70 6c 6f 61 64 2e 70 68 70 } //000webhostapp.com/upload.php  1
		$a_80_6 = {68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f } //https://pastebin.com/  1
		$a_80_7 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 22 3a 22 28 2e 2a 3f 29 } //encrypted_key":"(.*?)  1
		$a_80_8 = {2f 63 6f 6d 6d 61 6e 64 } ///command  1
		$a_80_9 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //SELECT * FROM AntivirusProduct  1
		$a_80_10 = {76 69 72 75 73 20 68 61 73 20 62 65 65 6e 20 68 69 64 64 65 6e } //virus has been hidden  1
		$a_80_11 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //\Google\Chrome\User Data  1
		$a_80_12 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 73 63 20 6d 69 6e 75 74 65 } //schtasks /create /sc minute  1
		$a_80_13 = {5c 57 69 6e 52 41 52 5c 57 69 6e 52 41 52 2e 65 78 65 20 61 20 2d 61 66 7a 69 70 } //\WinRAR\WinRAR.exe a -afzip  1
		$a_80_14 = {2e 70 6e 67 } //.png  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1) >=38
 
}