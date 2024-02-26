
rule Trojan_O97M_Maldade_RDA_MTB{
	meta:
		description = "Trojan:O97M/Maldade.RDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 73 63 72 49 50 74 49 6e 67 2e 66 69 6c 45 73 79 73 74 45 4d 4f 62 4a 65 63 74 22 29 } //02 00  CreateObject("scrIPtIng.filEsystEMObJect")
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 53 43 52 69 70 74 2e 53 48 45 6c 4c 22 29 } //02 00  CreateObject("wSCRipt.SHElL")
		$a_01_2 = {2e 57 52 69 54 45 20 53 74 72 52 65 76 65 72 73 65 28 } //00 00  .WRiTE StrReverse(
	condition:
		any of ($a_*)
 
}