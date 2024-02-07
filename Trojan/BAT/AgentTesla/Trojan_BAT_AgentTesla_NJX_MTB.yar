
rule Trojan_BAT_AgentTesla_NJX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 3d 00 00 04 18 9a 7e 3d 00 00 04 17 9a 20 de 07 00 00 95 e0 95 7e 3d 00 00 04 17 9a 20 71 0a 00 00 95 61 7e 3d 00 00 04 09 0d 17 9a 20 16 11 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NJX_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2d 00 08 00 00 1e 00 "
		
	strings :
		$a_01_0 = {24 65 64 31 66 34 30 65 36 2d 61 30 30 34 2d 34 64 35 38 2d 38 34 35 31 2d 31 38 37 33 65 39 38 31 37 63 30 37 } //0a 00  $ed1f40e6-a004-4d58-8451-1873e9817c07
		$a_01_1 = {08 17 58 0c 06 17 58 0a 06 20 00 24 01 00 fe 04 13 06 11 06 2d a6 } //0a 00 
		$a_01_2 = {50 4c 4f 4b 4d 34 30 00 63 63 63 00 50 4c 4f 4b 4d 34 31 00 42 69 74 6d 61 70 00 50 4c 4f 4b 4d 34 32 00 78 00 79 00 50 4c 4f 4b 4d 33 33 00 41 73 73 65 6d } //01 00  䱐䭏㑍0捣c䱐䭏㑍1楂浴灡倀佌䵋㈴砀礀倀佌䵋㌳䄀獳浥
		$a_01_3 = {6b 75 6c 69 53 41 50 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //01 00  kuliSAP1.Properties.Resources.resource
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_5 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //01 00  ColorTranslator
		$a_01_6 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_7 = {54 6f 57 69 6e 33 32 } //00 00  ToWin32
	condition:
		any of ($a_*)
 
}