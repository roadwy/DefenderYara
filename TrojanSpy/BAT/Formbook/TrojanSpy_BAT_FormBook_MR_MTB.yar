
rule TrojanSpy_BAT_FormBook_MR_MTB{
	meta:
		description = "TrojanSpy:BAT/FormBook.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 11 04 18 6f [0-04] 28 [0-04] 28 [0-04] 04 08 6f [0-04] 28 [0-04] 6a 61 b7 28 [0-04] 28 [0-04] 13 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}