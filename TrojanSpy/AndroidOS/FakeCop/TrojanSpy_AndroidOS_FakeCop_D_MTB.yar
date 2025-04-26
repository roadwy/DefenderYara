
rule TrojanSpy_AndroidOS_FakeCop_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeCop.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_00_0 = {35 34 0b 00 48 05 01 04 b7 a5 8d 55 4f 05 01 04 d8 04 04 01 28 f6 } //5
	condition:
		((#a_00_0  & 1)*5) >=5
 
}