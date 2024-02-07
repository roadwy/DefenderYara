
rule MonitoringTool_MSIL_Auxlogger{
	meta:
		description = "MonitoringTool:MSIL/Auxlogger,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 75 00 78 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 } //01 00  Aux Logger
		$a_01_1 = {5b 00 43 00 6f 00 70 00 69 00 65 00 64 00 20 00 74 00 6f 00 20 00 63 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 5d 00 } //01 00  [Copied to clipboard]
		$a_01_2 = {41 00 6e 00 74 00 69 00 20 00 56 00 69 00 72 00 75 00 73 00 3a 00 } //01 00  Anti Virus:
		$a_01_3 = {46 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 3a 00 } //01 00  Firewall:
		$a_03_4 = {06 02 08 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 1b 58 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0a 08 17 58 0c 08 09 31 d9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}