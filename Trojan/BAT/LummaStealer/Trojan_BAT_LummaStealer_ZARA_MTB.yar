
rule Trojan_BAT_LummaStealer_ZARA_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.ZARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 11 05 8f 1d 00 00 01 25 47 06 11 07 91 61 d2 52 11 05 17 58 13 05 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}