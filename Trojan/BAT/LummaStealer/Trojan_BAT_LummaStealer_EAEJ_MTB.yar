
rule Trojan_BAT_LummaStealer_EAEJ_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.EAEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 05 0b 16 0c 2b 12 03 08 02 03 08 91 08 04 28 60 00 00 06 9c 08 17 d6 0c 08 07 31 ea 03 0a 2b 00 06 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}