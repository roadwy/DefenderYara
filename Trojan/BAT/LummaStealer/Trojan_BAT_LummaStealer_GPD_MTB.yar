
rule Trojan_BAT_LummaStealer_GPD_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 d2 81 14 00 00 01 de 05 13 [0-20] 03 8e 69 3f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}