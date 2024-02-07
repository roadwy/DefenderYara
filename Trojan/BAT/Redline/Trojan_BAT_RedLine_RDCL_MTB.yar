
rule Trojan_BAT_RedLine_RDCL_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 63 79 63 6c 65 20 42 69 6f 20 4c 61 62 20 54 6f 6f 6c } //01 00  Recycle Bio Lab Tool
		$a_01_1 = {42 69 6f 54 65 63 68 } //01 00  BioTech
		$a_01_2 = {38 72 41 61 34 47 44 48 51 64 6d 46 4d 58 6c 30 71 4c } //01 00  8rAa4GDHQdmFMXl0qL
		$a_01_3 = {65 42 72 6c 38 34 34 63 51 70 72 39 4f 4e 5a 35 6c 45 } //00 00  eBrl844cQpr9ONZ5lE
	condition:
		any of ($a_*)
 
}