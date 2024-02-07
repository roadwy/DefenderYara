
rule HackTool_BAT_GalaxyLogger{
	meta:
		description = "HackTool:BAT/GalaxyLogger,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 65 72 66 6f 72 6d 53 74 65 61 6c } //01 00  performSteal
		$a_01_1 = {63 6c 69 70 62 6f 61 72 64 4c 6f 67 67 69 6e 67 } //01 00  clipboardLogging
		$a_01_2 = {7a 4b 65 79 62 6f 61 72 64 4c 6f 67 53 74 72 } //01 00  zKeyboardLogStr
		$a_01_3 = {67 65 74 53 65 6c 66 44 65 73 74 72 75 63 74 44 61 74 65 } //01 00  getSelfDestructDate
		$a_01_4 = {46 6f 72 63 65 53 74 65 61 6d 4c 6f 67 69 6e } //01 00  ForceSteamLogin
		$a_01_5 = {47 61 6c 61 78 79 4c 6f 67 67 65 72 } //00 00  GalaxyLogger
		$a_00_6 = {78 fc 00 } //00 09 
	condition:
		any of ($a_*)
 
}
rule HackTool_BAT_GalaxyLogger_2{
	meta:
		description = "HackTool:BAT/GalaxyLogger,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 6f 72 63 65 53 74 65 61 6d 4c 6f 67 69 6e } //05 00  ForceSteamLogin
		$a_01_1 = {47 61 6c 61 78 79 4c 6f 67 67 65 72 } //01 00  GalaxyLogger
		$a_01_2 = {73 00 6c 00 6f 00 6f 00 54 00 79 00 72 00 74 00 73 00 69 00 67 00 65 00 52 00 65 00 6c 00 62 00 61 00 73 00 69 00 44 00 } //01 00  slooTyrtsigeRelbasiD
		$a_01_3 = {72 00 67 00 4d 00 6b 00 73 00 61 00 54 00 65 00 6c 00 62 00 61 00 73 00 69 00 44 00 } //01 00  rgMksaTelbasiD
		$a_01_4 = {44 00 4d 00 43 00 65 00 6c 00 62 00 61 00 73 00 69 00 44 00 } //01 00  DMCelbasiD
		$a_01_5 = {41 00 55 00 4c 00 65 00 6c 00 62 00 61 00 6e 00 45 00 } //01 00  AULelbanE
		$a_01_6 = {73 00 6e 00 6f 00 69 00 74 00 70 00 4f 00 72 00 65 00 64 00 6c 00 6f 00 46 00 6f 00 4e 00 } //01 00  snoitpOredloFoN
		$a_01_7 = {67 00 69 00 66 00 6e 00 6f 00 43 00 65 00 6c 00 62 00 61 00 73 00 69 00 44 00 } //01 00  gifnoCelbasiD
		$a_01_8 = {52 00 53 00 65 00 6c 00 62 00 61 00 73 00 69 00 44 00 } //00 00  RSelbasiD
	condition:
		any of ($a_*)
 
}