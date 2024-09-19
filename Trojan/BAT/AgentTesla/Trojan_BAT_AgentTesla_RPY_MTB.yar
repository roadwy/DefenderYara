
rule Trojan_BAT_AgentTesla_RPY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 14 1f 16 5d 91 61 07 11 16 11 04 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RPY_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 0d 11 05 17 58 13 05 11 05 04 3f de ff ff ff 16 13 06 38 1b 00 00 00 06 09 5a 07 58 08 5d 13 04 0e 04 11 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RPY_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 7e 04 00 00 04 07 91 02 07 02 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 7e 04 00 00 04 8e 69 fe 04 0c 08 2d d9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RPY_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 1a 58 0a 00 11 07 17 58 13 07 11 07 07 fe 04 13 09 11 09 2d c7 00 11 06 17 58 13 06 11 06 07 fe 04 13 0a 11 0a 2d af } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RPY_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 09 18 6f 13 00 00 0a 1f 10 28 14 00 00 0a 13 04 11 04 16 3f 08 00 00 00 08 11 04 6f 15 00 00 0a 09 18 58 0d 09 07 6f 16 00 00 0a 32 d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RPY_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 03 00 00 0a 18 2c 03 17 2b 03 16 2b 00 2d 0d 26 7e 01 00 00 04 6f 04 00 00 0a 2b 07 80 01 00 00 04 2b ed 2a } //1
		$a_01_1 = {53 74 6f 70 77 61 74 63 68 } //1 Stopwatch
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_RPY_MTB_7{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {04 17 59 13 07 11 12 20 31 01 00 00 91 1f 68 59 13 10 38 5f fe ff ff 11 06 74 05 00 00 1b 11 07 8f 01 00 00 01 25 71 01 00 00 01 11 07 04 58 05 59 20 ff 00 00 00 5f d2 61 d2 81 01 00 00 01 11 12 20 9c 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RPY_MTB_8{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 04 1a 11 07 5a 09 19 1a 11 07 5a 58 91 9c 11 04 17 1a 11 07 5a 58 09 18 1a 11 07 5a 58 91 9c 11 04 18 1a 11 07 5a 58 09 17 1a 11 07 5a 58 91 9c 11 04 19 1a 11 07 5a 58 09 1a 11 07 5a 91 9c 00 11 07 17 58 13 07 11 07 1f 10 fe 04 13 08 11 08 2d ac } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RPY_MTB_9{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {16 0b 2b 22 11 04 06 07 28 bb 00 00 06 13 05 11 05 28 e0 00 00 0a 13 06 09 08 11 06 28 e1 00 00 0a 9c 07 17 58 0b 07 17 fe 04 13 07 11 07 2d d4 } //1
		$a_01_1 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
		$a_01_2 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_01_3 = {54 6f 42 79 74 65 } //1 ToByte
		$a_01_4 = {43 6f 6e 76 65 72 74 } //1 Convert
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_RPY_MTB_10{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {31 00 30 00 37 00 2e 00 31 00 37 00 32 00 2e 00 32 00 30 00 36 00 2e 00 31 00 32 00 30 00 2f 00 30 00 30 00 30 00 2f 00 } //1 107.172.206.120/000/
		$a_01_1 = {4a 00 79 00 65 00 67 00 75 00 76 00 7a 00 78 00 61 00 2e 00 70 00 6e 00 67 00 } //1 Jyeguvzxa.png
		$a_01_2 = {47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73 00 } //1 GetExportedTypes
		$a_01_3 = {48 74 74 70 43 6c 69 65 6e 74 } //1 HttpClient
		$a_01_4 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_5 = {46 69 6c 65 53 74 72 65 61 6d } //1 FileStream
		$a_01_6 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_01_7 = {45 6e 63 6f 64 69 6e 67 } //1 Encoding
		$a_01_8 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}