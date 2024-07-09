
rule Trojan_BAT_LummaStealer_CCCO_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.CCCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 01 11 02 11 01 93 20 ?? ?? ?? ?? 61 02 61 d1 9d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}