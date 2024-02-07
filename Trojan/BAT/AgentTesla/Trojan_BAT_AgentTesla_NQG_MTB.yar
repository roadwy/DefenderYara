
rule Trojan_BAT_AgentTesla_NQG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NQG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 00 78 00 65 00 2e 00 78 00 61 00 72 00 63 00 2f 00 39 00 30 00 38 00 39 00 3a 00 39 00 30 00 31 00 2e 00 31 00 33 00 2e 00 39 00 2e 00 36 00 37 00 31 00 2f 00 2f 00 3a 00 70 00 74 00 74 00 68 00 } //01 00  exe.xarc/9089:901.13.9.671//:ptth
		$a_81_1 = {46 53 41 2e 46 53 41 } //01 00  FSA.FSA
		$a_81_2 = {53 41 53 41 57 44 53 41 46 53 41 46 57 51 46 57 51 } //01 00  SASAWDSAFSAFWQFWQ
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_4 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}