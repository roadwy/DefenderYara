
rule PWS_BAT_Stealer_DHD_MTB{
	meta:
		description = "PWS:BAT/Stealer.DHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 33 20 26 20 44 65 6c 20 22 } //01 00  /C choice /C Y /N /D Y /T 3 & Del "
		$a_81_1 = {2f 57 69 6e 64 6f 77 73 2f 44 69 73 63 6f 72 64 } //01 00  /Windows/Discord
		$a_81_2 = {5c 42 69 74 63 6f 69 6e 43 6f 72 65 5c 77 61 6c 6c 65 74 2e 64 61 74 } //01 00  \BitcoinCore\wallet.dat
		$a_81_3 = {5c 64 69 73 63 6f 72 64 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 68 74 74 70 73 5f 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d } //01 00  \discord\Local Storage\https_discordapp.com
		$a_81_4 = {26 64 69 73 63 6f 72 64 3d } //01 00  &discord=
		$a_81_5 = {5c 42 72 6f 77 73 65 72 73 5c 50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //01 00  \Browsers\Passwords.txt
		$a_81_6 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 64 65 62 75 67 2e 74 78 74 } //00 00  C:\ProgramData\debug.txt
	condition:
		any of ($a_*)
 
}
rule PWS_BAT_Stealer_DHD_MTB_2{
	meta:
		description = "PWS:BAT/Stealer.DHD!MTB,SIGNATURE_TYPE_PEHSTR,18 00 18 00 0c 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 00 48 00 65 00 6c 00 6c 00 6f 00 20 00 46 00 42 00 49 00 5c 00 73 00 6f 00 75 00 72 00 63 00 65 00 5c 00 72 00 65 00 70 00 6f 00 73 00 5c 00 53 00 6f 00 72 00 61 00 6e 00 6f 00 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 2d 00 6d 00 61 00 73 00 74 00 65 00 72 00 5c 00 53 00 6f 00 72 00 61 00 6e 00 6f 00 5c 00 6f 00 62 00 6a 00 5c 00 44 00 65 00 62 00 75 00 67 00 5c 00 53 00 6f 00 72 00 61 00 6e 00 6f 00 2e 00 70 00 64 00 62 00 } //0a 00  \Hello FBI\source\repos\SoranoStealer-master\Sorano\obj\Debug\Sorano.pdb
		$a_01_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 68 00 6f 00 6b 00 61 00 67 00 65 00 2e 00 72 00 75 00 2f 00 2f 00 } //0a 00  https://hokage.ru//
		$a_01_2 = {5c 00 5c 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 20 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 5c 00 } //0a 00  \\discord\Local Storage\
		$a_01_3 = {5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 4d 00 69 00 6e 00 65 00 63 00 72 00 61 00 66 00 74 00 4f 00 6e 00 6c 00 79 00 5c 00 75 00 73 00 65 00 72 00 64 00 61 00 74 00 61 00 } //0a 00  \Applications\MinecraftOnly\userdata
		$a_01_4 = {5c 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2e 00 6a 00 70 00 67 00 } //01 00  \desktop.jpg
		$a_01_5 = {4c 00 69 00 73 00 74 00 5f 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 2e 00 68 00 74 00 6d 00 6c 00 } //01 00  List_Password.html
		$a_01_6 = {5c 00 70 00 61 00 73 00 73 00 2e 00 6c 00 6f 00 67 00 } //01 00  \pass.log
		$a_01_7 = {5c 00 43 00 61 00 6d 00 50 00 69 00 63 00 74 00 75 00 72 00 65 00 2e 00 70 00 6e 00 67 00 } //01 00  \CamPicture.png
		$a_01_8 = {5c 00 77 00 61 00 6c 00 6c 00 65 00 74 00 2e 00 64 00 61 00 74 00 } //01 00  \wallet.dat
		$a_01_9 = {2e 00 64 00 6f 00 63 00 78 00 } //01 00  .docx
		$a_01_10 = {42 00 69 00 74 00 63 00 6f 00 69 00 6e 00 } //01 00  Bitcoin
		$a_01_11 = {5c 00 46 00 69 00 6c 00 65 00 73 00 5c 00 } //00 00  \Files\
	condition:
		any of ($a_*)
 
}