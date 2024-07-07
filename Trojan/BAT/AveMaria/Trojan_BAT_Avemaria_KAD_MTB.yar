
rule Trojan_BAT_Avemaria_KAD_MTB{
	meta:
		description = "Trojan:BAT/Avemaria.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 03 1e 5d 10 01 03 16 fe 04 0a 06 2c 07 00 1e 03 58 10 01 00 02 03 1f 1f 5f 62 02 1e 03 59 1f 1f 5f 63 60 d2 0b 2b 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}