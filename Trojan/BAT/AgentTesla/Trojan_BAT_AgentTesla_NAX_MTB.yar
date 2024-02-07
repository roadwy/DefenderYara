
rule Trojan_BAT_AgentTesla_NAX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {23 66 73 64 73 66 64 73 66 66 73 64 66 73 6b 61 68 66 68 66 61 6e 6b 6b 6b 61 73 66 23 } //01 00  #fsdsfdsffsdfskahfhfankkkasf#
		$a_01_1 = {23 67 73 64 67 67 64 6c 6c 66 73 66 73 64 66 66 73 66 6c 6c 6c 66 67 66 6c 6c 6f 6b 6f 73 61 64 73 61 64 67 67 67 67 67 23 } //01 00  #gsdggdllfsfsdffsflllfgfllokosadsadggggg#
		$a_01_2 = {23 66 73 61 6c 6c 75 69 69 6a 75 69 64 73 66 73 64 66 66 66 73 64 66 64 73 66 68 66 61 73 61 66 2e 64 6c 6c 23 } //01 00  #fsalluiijuidsfsdfffsdfdsfhfasaf.dll#
		$a_01_3 = {23 66 61 66 64 61 73 67 73 66 66 73 64 66 64 6b 67 66 69 6f 69 6f 61 61 61 61 61 6f 61 61 61 64 73 73 73 61 66 2e 64 6c 6c 23 } //01 00  #fafdasgsffsdfdkgfioioaaaaaoaaadsssaf.dll#
		$a_01_4 = {23 67 64 66 73 61 66 66 64 73 66 66 73 64 66 64 73 6c 66 73 61 66 67 66 6c 6c 6c 6c 73 2e 64 6c 6c 23 } //01 00  #gdfsaffdsffsdfdslfsafgflllls.dll#
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}