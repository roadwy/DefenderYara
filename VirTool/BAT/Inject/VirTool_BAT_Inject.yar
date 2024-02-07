
rule VirTool_BAT_Inject{
	meta:
		description = "VirTool:BAT/Inject,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 35 3a 6f 42 3e 3f 55 64 3d 49 3b 2a 3e 2c 3f 57 2f 2d 39 36 68 64 60 00 41 74 74 72 69 62 75 74 65 } //01 00  㕨漺㹂唿㵤㭉㸪㼬⽗㤭栶恤䄀瑴楲畢整
		$a_01_1 = {62 61 62 69 67 67 62 6f 79 2e 64 64 6e 73 2e 6e 65 74 } //01 00  babiggboy.ddns.net
		$a_01_2 = {6d 6f 64 65 6d 20 6b 69 6c 6c 61 } //00 00  modem killa
	condition:
		any of ($a_*)
 
}
rule VirTool_BAT_Inject_2{
	meta:
		description = "VirTool:BAT/Inject,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 75 72 69 49 6e 69 6d 61 2e 65 78 65 00 66 75 72 69 49 6e 69 6d 61 00 } //01 00 
		$a_02_1 = {72 00 69 00 74 00 6d 00 61 00 74 00 90 01 02 67 00 72 00 61 00 73 00 75 00 74 00 61 00 90 01 02 66 00 75 00 72 00 69 00 49 00 6e 00 69 00 6d 00 61 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 90 00 } //01 00 
		$a_00_2 = {63 00 75 00 6d 00 74 00 65 00 2e 00 74 00 61 00 6d 00 62 00 61 00 6c 00 } //01 00  cumte.tambal
		$a_01_3 = {43 75 6d 74 65 54 61 6d 62 61 6c } //01 00  CumteTambal
		$a_01_4 = {13 05 11 05 13 06 09 11 06 61 13 07 11 07 d1 13 08 06 11 08 6f 35 00 00 0a 26 00 07 13 09 11 09 17 58 0b } //00 00 
	condition:
		any of ($a_*)
 
}