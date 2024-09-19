
rule Trojan_BAT_LummaStealer_CCJB_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.CCJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 06 03 04 6f 17 00 00 0a 0b 02 07 28 05 00 00 06 0c de 14 07 2c 06 07 6f 18 00 00 0a dc 06 2c 06 06 6f 18 00 00 0a dc 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}