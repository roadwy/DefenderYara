
rule Trojan_BAT_LummaStealer_GPPF_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.GPPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 d2 52 11 30 17 58 13 30 11 30 03 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}