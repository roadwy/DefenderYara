
rule Trojan_BAT_LummaStealer_KAD_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 11 09 8f ?? 00 00 01 25 71 ?? 00 00 01 09 11 ?? 91 61 d2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}