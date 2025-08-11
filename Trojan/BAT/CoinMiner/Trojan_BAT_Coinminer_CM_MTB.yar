
rule Trojan_BAT_Coinminer_CM_MTB{
	meta:
		description = "Trojan:BAT/Coinminer.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 03 07 58 91 0d 07 17 58 0b 09 20 80 00 00 00 5f 16 fe 01 13 05 11 05 2d 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}