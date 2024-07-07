
rule Trojan_BAT_LummaStealer_SPDO_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.SPDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 17 58 20 00 01 00 00 5d 0b 08 09 07 91 58 20 00 01 00 00 5d 0c 16 13 0b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}