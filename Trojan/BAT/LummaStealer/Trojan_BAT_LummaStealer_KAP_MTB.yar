
rule Trojan_BAT_LummaStealer_KAP_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.KAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 1d 17 6f ?? 00 00 0a 91 61 d2 81 ?? 00 00 01 11 13 17 58 13 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}