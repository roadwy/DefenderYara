
rule Trojan_BAT_LummaStealer_KAF_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d4 91 61 07 11 90 01 01 17 6a 58 07 8e 69 6a 5d d4 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}