
rule Trojan_BAT_LummaStealer_ALS_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.ALS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 3a 00 02 06 02 06 91 66 d2 9c 02 06 8f 36 00 00 01 25 71 36 00 00 01 1f 79 59 d2 81 36 00 00 01 02 06 8f 36 00 00 01 25 71 36 00 00 01 1f 57 59 d2 81 36 00 00 01 00 06 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}