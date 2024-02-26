
rule Trojan_BAT_AgentTesla_RPY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {08 11 14 1f 16 5d 91 61 07 11 16 11 04 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPY_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 04 0d 11 05 17 58 13 05 11 05 04 3f de ff ff ff 16 13 06 38 1b 00 00 00 06 09 5a 07 58 08 5d 13 04 0e 04 11 04 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPY_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 06 1a 58 0a 00 11 07 17 58 13 07 11 07 07 fe 04 13 09 11 09 2d c7 00 11 06 17 58 13 06 11 06 07 fe 04 13 0a 11 0a 2d af } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPY_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 03 00 00 0a 18 2c 03 17 2b 03 16 2b 00 2d 0d 26 7e 01 00 00 04 6f 04 00 00 0a 2b 07 80 01 00 00 04 2b ed 2a } //01 00 
		$a_01_1 = {53 74 6f 70 77 61 74 63 68 } //00 00  Stopwatch
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPY_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {16 0b 2b 22 11 04 06 07 28 bb 00 00 06 13 05 11 05 28 e0 00 00 0a 13 06 09 08 11 06 28 e1 00 00 0a 9c 07 17 58 0b 07 17 fe 04 13 07 11 07 2d d4 } //01 00 
		$a_01_1 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //01 00  ColorTranslator
		$a_01_2 = {54 6f 57 69 6e 33 32 } //01 00  ToWin32
		$a_01_3 = {54 6f 42 79 74 65 } //01 00  ToByte
		$a_01_4 = {43 6f 6e 76 65 72 74 } //00 00  Convert
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPY_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 00 30 00 37 00 2e 00 31 00 37 00 32 00 2e 00 32 00 30 00 36 00 2e 00 31 00 32 00 30 00 2f 00 30 00 30 00 30 00 2f 00 } //01 00  107.172.206.120/000/
		$a_01_1 = {4a 00 79 00 65 00 67 00 75 00 76 00 7a 00 78 00 61 00 2e 00 70 00 6e 00 67 00 } //01 00  Jyeguvzxa.png
		$a_01_2 = {47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73 00 } //01 00  GetExportedTypes
		$a_01_3 = {48 74 74 70 43 6c 69 65 6e 74 } //01 00  HttpClient
		$a_01_4 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_5 = {46 69 6c 65 53 74 72 65 61 6d } //01 00  FileStream
		$a_01_6 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_01_7 = {45 6e 63 6f 64 69 6e 67 } //01 00  Encoding
		$a_01_8 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}