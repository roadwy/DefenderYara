
rule Trojan_BAT_AgentTesla_NQF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NQF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {61 6d 74 65 63 68 70 72 69 6e 74 69 6e 67 2e 63 6f 6d } //01 00  amtechprinting.com
		$a_81_1 = {45 70 6f 67 61 67 63 73 67 79 66 62 6b 62 6d 68 70 7a 79 } //01 00  Epogagcsgyfbkbmhpzy
		$a_81_2 = {71 77 65 72 74 79 5f 46 74 6c 76 71 65 63 61 } //01 00  qwerty_Ftlvqeca
		$a_81_3 = {4b 6e 64 67 64 69 74 73 76 69 6d 6c 6d 79 74 64 68 62 69 67 7a 65 6c 2e 55 6d 70 65 70 78 65 69 } //01 00  Kndgditsvimlmytdhbigzel.Umpepxei
		$a_81_4 = {44 69 70 6c 62 74 6c 62 62 76 78 79 71 66 73 63 73 76 } //01 00  Diplbtlbbvxyqfscsv
		$a_01_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}