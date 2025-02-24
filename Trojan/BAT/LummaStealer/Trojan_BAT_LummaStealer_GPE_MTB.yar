
rule Trojan_BAT_LummaStealer_GPE_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.GPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 11 09 11 05 5a 06 58 17 6a 58 13 0b 07 11 0b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}