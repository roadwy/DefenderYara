
rule Trojan_BAT_Formbook_DH_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 64 62 35 63 66 33 35 65 2d 64 61 64 39 2d 34 63 39 32 2d 38 32 37 39 2d 61 36 37 62 35 62 39 35 61 31 63 30 } //01 00  $db5cf35e-dad9-4c92-8279-a67b5b95a1c0
		$a_81_1 = {53 6f 63 69 61 6c 5f 43 6c 75 62 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Social_Club.Resources
		$a_81_2 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_3 = {49 43 72 79 70 74 6f 54 72 61 6e 73 66 6f 72 6d } //01 00  ICryptoTransform
		$a_81_4 = {73 65 74 5f 48 69 64 65 53 65 6c 65 63 74 69 6f 6e } //01 00  set_HideSelection
		$a_81_5 = {67 65 74 5f 43 6f 6e 6e 65 63 74 69 6f 6e } //00 00  get_Connection
	condition:
		any of ($a_*)
 
}