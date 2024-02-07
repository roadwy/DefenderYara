
rule Trojan_BAT_CryptInject_PD_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 36 64 38 62 36 65 39 66 2d 32 37 62 33 2d 34 31 63 38 2d 39 39 62 33 2d 63 61 64 63 39 32 37 37 33 66 61 30 } //01 00  $6d8b6e9f-27b3-41c8-99b3-cadc92773fa0
		$a_81_1 = {67 65 74 5f 4d 64 69 43 68 69 6c 64 72 65 6e } //01 00  get_MdiChildren
		$a_81_2 = {73 65 74 5f 4d 64 69 50 61 72 65 6e 74 } //01 00  set_MdiParent
		$a_81_3 = {4d 44 49 50 61 72 65 6e 74 31 } //01 00  MDIParent1
		$a_81_4 = {44 61 6d 61 2e 4d 79 } //01 00  Dama.My
		$a_81_5 = {44 61 6d 61 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Dama.My.Resources
		$a_81_6 = {44 61 6d 61 2e 4d 44 49 50 61 72 65 6e 74 31 2e 72 65 73 6f 75 72 63 65 73 } //00 00  Dama.MDIParent1.resources
	condition:
		any of ($a_*)
 
}