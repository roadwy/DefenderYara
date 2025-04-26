
rule Trojan_BAT_LummaStealer_KAN_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.KAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 13 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 1f 91 61 d2 81 ?? 00 00 01 11 13 17 58 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}