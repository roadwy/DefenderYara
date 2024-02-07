
rule Trojan_BAT_Remcos_NEC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 73 16 00 00 0a 0c 00 07 08 6f 19 00 00 0a 00 08 6f 1b 00 00 0a 0d de 16 } //01 00 
		$a_01_1 = {56 00 73 00 76 00 61 00 71 00 76 00 61 00 7a 00 77 00 76 00 74 00 67 00 6e 00 69 00 78 00 6f 00 } //00 00  Vsvaqvazwvtgnixo
	condition:
		any of ($a_*)
 
}