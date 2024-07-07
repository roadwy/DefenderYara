
rule Trojan_BAT_LokiBot_CM_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {67 6c 6f 62 61 6c 47 61 6d 65 53 74 61 74 65 } //3 globalGameState
		$a_81_1 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //3 DebuggerNonUserCodeAttribute
		$a_81_2 = {67 65 74 5f 52 53 41 50 4b 43 53 31 53 48 41 33 38 34 } //3 get_RSAPKCS1SHA384
		$a_81_3 = {47 68 6f 73 74 50 61 72 74 79 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //3 GhostParty.Properties.Resources
		$a_81_4 = {47 61 6c 61 78 79 20 4d 61 6e } //3 Galaxy Man
		$a_81_5 = {4d 6f 76 65 47 75 65 73 74 44 6f 77 6e 48 61 6c 6c 77 61 79 } //3 MoveGuestDownHallway
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}