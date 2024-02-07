
rule Trojan_BAT_AsyncRat_CXIQ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CXIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 63 68 67 6e 4f 61 49 44 } //01 00  nchgnOaID
		$a_01_1 = {6e 4e 54 61 78 62 6e 46 42 6f } //01 00  nNTaxbnFBo
		$a_01_2 = {4d 56 72 54 53 6f 72 51 75 } //01 00  MVrTSorQu
		$a_01_3 = {61 51 4f 6d 65 61 64 } //01 00  aQOmead
		$a_01_4 = {62 75 66 72 4e 54 61 78 62 6e 46 42 6f } //00 00  bufrNTaxbnFBo
	condition:
		any of ($a_*)
 
}