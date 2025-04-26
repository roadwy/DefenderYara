
rule TrojanSpy_BAT_Banker_EAFR_MTB{
	meta:
		description = "TrojanSpy:BAT/Banker.EAFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 00 40 01 00 8d 53 00 00 01 0a 2b 09 03 06 16 07 6f a4 00 00 0a 02 06 16 06 8e 69 6f 9b 00 00 0a 25 0b 2d e8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}