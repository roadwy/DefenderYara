
rule Trojan_BAT_LummaStealer_ARA_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e3 06 0d 2b 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}