
rule Trojan_BAT_AgentTesla_LVE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 63 35 36 65 62 30 38 63 2d 30 30 35 35 2d 34 39 63 36 2d 39 38 36 37 2d 37 62 30 62 33 36 38 31 33 31 39 61 } //01 00  $c56eb08c-0055-49c6-9867-7b0b3681319a
		$a_01_1 = {43 65 6e 74 72 61 6c 20 48 61 72 64 77 61 72 65 } //01 00  Central Hardware
		$a_01_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_4 = {74 6f 63 69 72 70 61 } //01 00  tocirpa
		$a_81_5 = {6f 64 61 63 6f 76 61 } //01 00  odacova
		$a_81_6 = {6e 69 61 74 6e 61 6c 70 } //01 00  niatnalp
		$a_81_7 = {65 65 68 63 79 6c } //00 00  eehcyl
	condition:
		any of ($a_*)
 
}