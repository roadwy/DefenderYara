
rule Backdoor_BAT_Ploutos_B_bit{
	meta:
		description = "Backdoor:BAT/Ploutos.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 69 6e 69 6e 67 54 61 73 6b } //01 00  MiningTask
		$a_01_1 = {4c 6f 67 67 65 72 54 61 73 6b } //02 00  LoggerTask
		$a_81_2 = {50 72 6f 74 65 75 73 48 54 54 50 42 6f 74 6e 65 74 } //01 00  ProteusHTTPBotnet
		$a_01_3 = {52 65 67 69 73 74 65 72 42 6f 74 } //01 00  RegisterBot
		$a_01_4 = {6b 65 79 62 6f 61 72 64 48 6f 6f 6b 50 72 6f 63 } //01 00  keyboardHookProc
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 00 4c 6f 61 64 41 6e 64 53 74 61 72 74 46 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}