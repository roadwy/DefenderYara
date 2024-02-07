
rule Worm_BAT_Bitbogar_A{
	meta:
		description = "Worm:BAT/Bitbogar.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 72 6f 74 68 65 72 43 6f 6e 66 69 67 } //01 00  BrotherConfig
		$a_01_1 = {45 6d 61 69 6c 4b 65 79 6c 6f 67 67 65 72 } //01 00  EmailKeylogger
		$a_01_2 = {45 6d 61 69 6c 59 61 68 6f 6f 43 61 6d } //01 00  EmailYahooCam
		$a_01_3 = {53 70 72 65 61 64 54 6f 55 73 62 } //01 00  SpreadToUsb
		$a_01_4 = {53 70 72 65 61 64 54 6f 53 74 61 72 74 75 70 } //01 00  SpreadToStartup
		$a_01_5 = {53 70 72 65 61 64 54 6f 53 79 73 74 65 6d } //00 00  SpreadToSystem
		$a_00_6 = {5d 04 00 } //00 cd 
	condition:
		any of ($a_*)
 
}