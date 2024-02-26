
rule Trojan_AndroidOS_SpyAgent_X{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.X,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {26 61 63 74 69 6f 6e 3d 69 6d 70 6f 72 74 63 6f 6e 74 61 63 74 } //02 00  &action=importcontact
		$a_01_1 = {2f 75 70 5f 66 69 6c 65 2e 70 68 70 3f 72 65 73 70 6f 6e 73 65 3d 74 72 75 65 26 69 64 3d } //02 00  /up_file.php?response=true&id=
		$a_01_2 = {26 61 63 74 69 6f 6e 3d 6f 66 66 73 74 61 74 75 73 65 6e } //00 00  &action=offstatusen
	condition:
		any of ($a_*)
 
}