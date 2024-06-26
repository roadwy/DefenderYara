
rule PWS_Win32_Kheagol_E{
	meta:
		description = "PWS:Win32/Kheagol.E,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0c 00 00 03 00 "
		
	strings :
		$a_01_0 = {43 52 45 44 55 49 2e 64 6c 6c } //03 00  CREDUI.dll
		$a_01_1 = {73 74 61 72 74 75 70 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 25 75 26 62 74 79 70 65 3d 25 75 } //03 00  startup.php?id=%s&ver=%u&btype=%u
		$a_01_2 = {64 61 74 61 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 25 75 26 6d 3d 25 75 26 62 74 79 70 65 3d 25 75 } //03 00  data.php?id=%s&ver=%u&m=%u&btype=%u
		$a_01_3 = {69 64 69 3d 25 75 } //02 00  idi=%u
		$a_01_4 = {43 52 45 44 41 54 3a } //01 00  CREDAT:
		$a_01_5 = {43 72 65 64 55 49 50 72 6f 6d 70 74 46 6f 72 43 72 65 64 65 6e 74 69 61 6c 73 } //01 00  CredUIPromptForCredentials
		$a_01_6 = {50 46 58 49 6d 70 6f 72 74 43 65 72 74 53 74 6f 72 65 } //01 00  PFXImportCertStore
		$a_01_7 = {64 61 74 61 2e 70 68 70 } //01 00  data.php
		$a_01_8 = {73 74 61 72 74 75 70 2e 70 68 70 } //01 00  startup.php
		$a_01_9 = {68 8d bd c1 3f } //01 00 
		$a_01_10 = {c6 44 24 38 69 } //01 00 
		$a_01_11 = {68 37 bd 4f 84 } //00 00 
	condition:
		any of ($a_*)
 
}