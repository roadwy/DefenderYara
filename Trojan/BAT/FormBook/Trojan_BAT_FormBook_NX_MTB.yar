
rule Trojan_BAT_FormBook_NX_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 36 62 66 66 37 33 33 32 2d 31 31 62 34 2d 34 37 65 61 2d 39 63 63 36 2d 32 36 64 32 39 65 65 34 33 32 34 36 } //01 00  $6bff7332-11b4-47ea-9cc6-26d29ee43246
		$a_01_1 = {54 68 65 51 75 65 73 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  TheQuest.Properties.Resources.resources
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}