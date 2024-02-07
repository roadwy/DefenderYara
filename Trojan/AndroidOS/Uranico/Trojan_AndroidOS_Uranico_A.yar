
rule Trojan_AndroidOS_Uranico_A{
	meta:
		description = "Trojan:AndroidOS/Uranico.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {75 72 61 6e 61 69 2f 41 6e 73 77 65 72 24 } //01 00  uranai/Answer$
		$a_01_1 = {63 6f 6e 66 69 67 43 68 61 6e 67 65 73 } //01 00  configChanges
		$a_01_2 = {67 65 6f 3a 30 2c 30 3f 71 3d 64 6f 6e 75 74 73 } //01 00  geo:0,0?q=donuts
		$a_01_3 = {52 45 46 45 4c 45 52 5f 52 45 51 55 45 53 54 5f 4e 41 4d 45 } //00 00  REFELER_REQUEST_NAME
	condition:
		any of ($a_*)
 
}