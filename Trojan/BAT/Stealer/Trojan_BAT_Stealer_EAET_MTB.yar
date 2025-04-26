
rule Trojan_BAT_Stealer_EAET_MTB{
	meta:
		description = "Trojan:BAT/Stealer.EAET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 a3 05 00 00 01 0c 08 6f 16 00 00 0a 03 28 17 00 00 0a 39 02 00 00 00 08 2a 07 17 58 0b 07 06 8e 69 32 db } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}