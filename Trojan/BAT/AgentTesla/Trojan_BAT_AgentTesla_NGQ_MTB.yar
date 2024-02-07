
rule Trojan_BAT_AgentTesla_NGQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 90 01 03 0a 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a 07 6f 90 01 03 0a 0d de 1e 90 00 } //01 00 
		$a_03_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 90 02 02 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 90 00 } //01 00 
		$a_81_2 = {43 30 41 55 77 42 73 41 47 55 41 5a 51 42 77 41 43 41 41 4c 51 42 7a 41 43 41 41 4d 51 41 31 41 41 3d 3d } //01 00  C0AUwBsAGUAZQBwACAALQBzACAAMQA1AA==
		$a_81_3 = {2d 65 6e 63 20 55 77 42 30 41 47 45 41 63 67 42 30 41 } //01 00  -enc UwB0AGEAcgB0A
		$a_81_4 = {70 6f 77 65 72 73 68 65 6c 6c } //01 00  powershell
		$a_01_5 = {47 7a 69 70 53 74 72 65 61 6d } //00 00  GzipStream
	condition:
		any of ($a_*)
 
}