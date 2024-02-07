
rule HackTool_MacOS_Keygen_A_MTB{
	meta:
		description = "HackTool:MacOS/Keygen.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 63 64 73 61 5f 70 61 74 74 65 72 6e } //01 00  ecdsa_pattern
		$a_01_1 = {61 64 65 73 6b 6c 6f 76 65 72 73 } //01 00  adesklovers
		$a_01_2 = {73 79 73 74 65 6d 2e 70 72 69 76 69 6c 65 67 65 2e 61 64 6d 69 6e } //01 00  system.privilege.admin
		$a_01_3 = {64 6f 4d 65 6d 50 61 74 63 68 } //01 00  doMemPatch
		$a_01_4 = {4b 65 79 47 65 6e } //01 00  KeyGen
		$a_01_5 = {65 78 65 63 4d 65 41 73 52 6f 6f 74 } //01 00  execMeAsRoot
		$a_01_6 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 70 61 74 63 68 65 64 } //00 00  Successfully patched
	condition:
		any of ($a_*)
 
}