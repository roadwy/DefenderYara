
rule TrojanSpy_BAT_FormBook_MR_MTB{
	meta:
		description = "TrojanSpy:BAT/FormBook.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 11 04 18 6f 90 02 04 28 90 02 04 28 90 02 04 04 08 6f 90 02 04 28 90 02 04 6a 61 b7 28 90 02 04 28 90 02 04 13 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}