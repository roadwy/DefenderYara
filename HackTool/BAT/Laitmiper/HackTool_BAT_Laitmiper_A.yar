
rule HackTool_BAT_Laitmiper_A{
	meta:
		description = "HackTool:BAT/Laitmiper.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 53 4e 5f 46 72 65 65 7a 65 72 2e 4d 79 } //01 00  MSN_Freezer.My
		$a_01_1 = {43 00 72 00 65 00 61 00 74 00 6f 00 20 00 44 00 61 00 20 00 50 00 61 00 6e 00 69 00 6e 00 6f 00 44 00 61 00 6e 00 69 00 6c 00 6f 00 } //01 00  Creato Da PaninoDanilo
		$a_01_2 = {70 00 61 00 6e 00 69 00 6e 00 6f 00 64 00 61 00 6e 00 69 00 6c 00 6f 00 2e 00 61 00 6c 00 74 00 65 00 72 00 76 00 69 00 73 00 74 00 61 00 2e 00 6f 00 72 00 67 00 } //01 00  paninodanilo.altervista.org
		$a_01_3 = {4d 00 53 00 4e 00 5f 00 46 00 72 00 65 00 65 00 7a 00 65 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  MSN_Freezer.Resources
	condition:
		any of ($a_*)
 
}