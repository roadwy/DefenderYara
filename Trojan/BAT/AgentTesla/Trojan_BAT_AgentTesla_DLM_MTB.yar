
rule Trojan_BAT_AgentTesla_DLM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 00 54 00 2d 00 6f 00 2d 00 57 00 2d 00 69 00 2d 00 6e 00 2d 00 33 00 2d 00 32 00 2d 00 } //01 00  -T-o-W-i-n-3-2-
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_2 = {00 47 65 74 54 79 70 65 00 } //01 00 
		$a_01_3 = {00 47 65 74 50 69 78 65 6c 00 } //01 00  䜀瑥楐數l
		$a_01_4 = {00 43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 00 } //01 00 
		$a_01_5 = {50 00 55 00 2e 00 6f 00 6f 00 } //01 00  PU.oo
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_7 = {24 30 42 46 43 41 44 37 34 2d 31 32 32 36 2d 34 45 45 41 2d 38 38 42 30 2d 39 46 38 31 30 46 46 39 34 30 46 35 } //00 00  $0BFCAD74-1226-4EEA-88B0-9F810FF940F5
	condition:
		any of ($a_*)
 
}