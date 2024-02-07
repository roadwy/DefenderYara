
rule Trojan_BAT_Lokibot_RWA_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 64 32 36 35 62 65 38 32 2d 62 63 36 38 2d 34 65 36 65 2d 61 62 65 39 2d 65 38 33 32 38 38 36 32 36 35 64 62 } //01 00  $d265be82-bc68-4e6e-abe9-e832886265db
		$a_81_1 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_2 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_3 = {67 65 74 5f 44 65 73 6b 74 6f 70 } //01 00  get_Desktop
		$a_81_4 = {67 65 74 5f 4b 65 79 43 68 61 72 } //01 00  get_KeyChar
		$a_81_5 = {67 65 74 5f 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //01 00  get_ResourceManager
		$a_81_6 = {4b 65 79 50 72 65 73 73 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //00 00  KeyPressEventHandler
	condition:
		any of ($a_*)
 
}