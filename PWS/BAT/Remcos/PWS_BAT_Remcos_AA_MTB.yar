
rule PWS_BAT_Remcos_AA_MTB{
	meta:
		description = "PWS:BAT/Remcos.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 53 70 6c 61 73 68 53 63 72 65 65 6e 31 } //01 00  get_SplashScreen1
		$a_01_1 = {61 64 64 5f 4d 6f 75 73 65 44 6f 75 62 6c 65 43 6c 69 63 6b } //01 00  add_MouseDoubleClick
		$a_01_2 = {4e 6f 74 69 66 79 49 63 6f 6e 31 5f 4d 6f 75 73 65 43 6c 69 63 6b } //01 00  NotifyIcon1_MouseClick
		$a_01_3 = {73 65 74 5f 43 68 65 63 6b 4f 6e 43 6c 69 63 6b } //01 00  set_CheckOnClick
		$a_01_4 = {67 65 74 5f 41 63 63 65 73 73 54 6f 54 68 65 4f 66 66 69 63 69 61 6c 57 65 62 73 69 74 65 4f 6e 47 69 74 48 75 62 54 6f 6f 6c 53 74 72 69 70 4d 65 6e 75 49 74 65 6d } //01 00  get_AccessToTheOfficialWebsiteOnGitHubToolStripMenuItem
		$a_01_5 = {41 75 74 6f 53 61 76 65 53 65 74 74 69 6e 67 73 } //01 00  AutoSaveSettings
		$a_01_6 = {4b 65 79 50 72 65 73 73 45 76 65 6e 74 41 72 67 73 } //01 00  KeyPressEventArgs
		$a_01_7 = {61 64 64 5f 4b 65 79 50 72 65 73 73 } //01 00  add_KeyPress
		$a_01_8 = {63 00 6f 00 6e 00 66 00 69 00 67 00 5c 00 6e 00 61 00 6d 00 65 00 2d 00 6c 00 69 00 73 00 74 00 2e 00 78 00 6d 00 6c 00 } //01 00  config\name-list.xml
		$a_01_9 = {63 00 6f 00 6e 00 66 00 69 00 67 00 5c 00 6a 00 6f 00 62 00 2d 00 6c 00 69 00 73 00 74 00 2e 00 78 00 6d 00 6c 00 } //00 00  config\job-list.xml
	condition:
		any of ($a_*)
 
}