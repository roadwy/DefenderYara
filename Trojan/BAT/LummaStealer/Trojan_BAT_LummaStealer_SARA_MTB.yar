
rule Trojan_BAT_LummaStealer_SARA_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.SARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 11 13 8f 14 00 00 01 25 71 14 00 00 01 06 11 1c 91 61 d2 81 14 00 00 01 11 13 17 58 13 13 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}