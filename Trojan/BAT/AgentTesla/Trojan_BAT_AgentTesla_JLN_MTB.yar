
rule Trojan_BAT_AgentTesla_JLN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {0c 43 74 42 6d 2d 27 42 6d 2d 27 42 6d 2d 27 19 05 2e 26 48 6d 2d 27 19 05 28 26 d2 6d 2d 27 } //01 00 
		$a_81_1 = {05 29 26 50 6d 2d 27 24 02 d0 27 41 6d 2d 27 10 18 28 26 67 6d 2d 27 10 18 29 26 51 6d 2d 27 10 18 2e 26 57 6d 2d 27 19 05 2c 26 } //01 00 
		$a_81_2 = {4b 6d 2d 27 42 6d 2c 27 d8 6d 2d 27 14 18 29 26 43 6d 2d 27 14 18 d2 27 43 6d 2d 27 42 6d ba 27 43 6d 2d 27 14 18 2f 26 43 6d 2d 27 52 69 63 68 42 6d 2d } //01 00 
		$a_81_3 = {44 4f 53 20 6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00 06 0c 43 74 42 6d 2d 27 42 6d 2d 27 42 } //01 00 
		$a_81_4 = {43 00 4f 00 4d 00 53 00 50 00 45 00 43 00 00 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 } //01 00 
		$a_81_5 = {78 70 78 78 78 78 } //01 00  xpxxxx
		$a_81_6 = {4c 43 4d 61 70 53 74 72 69 6e 67 45 78 } //01 00  LCMapStringEx
		$a_81_7 = {4c 6f 63 61 6c 65 4e 61 6d 65 54 6f 4c 43 49 44 } //01 00  LocaleNameToLCID
		$a_81_8 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_81_9 = {5c 63 6f 6d 6d 61 6e 64 5c 73 74 61 72 74 2e 65 78 65 } //00 00  \command\start.exe
	condition:
		any of ($a_*)
 
}