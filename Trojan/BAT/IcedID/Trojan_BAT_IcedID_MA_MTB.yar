
rule Trojan_BAT_IcedID_MA_MTB{
	meta:
		description = "Trojan:BAT/IcedID.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 04 7e 01 00 00 04 7b 0b 00 00 0a 16 28 11 00 00 0a 13 05 02 11 05 11 04 28 12 00 00 0a 72 3b 00 00 70 72 55 00 00 70 11 04 72 59 00 00 70 28 13 00 00 0a 28 14 00 00 0a 26 de 03 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}