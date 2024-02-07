
rule Trojan_O97M_Emotet_RDD_MTB{
	meta:
		description = "Trojan:O97M/Emotet.RDD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {22 4a 4a 43 43 42 42 22 } //01 00  "JJCCBB"
		$a_00_1 = {6f 6e 22 2c 22 75 72 6c 64 6f 77 6e 6c 6f 61 64 74 6f 66 69 6c } //01 00  on","urldownloadtofil
		$a_00_2 = {2e 6f 63 78 } //00 00  .ocx
	condition:
		any of ($a_*)
 
}