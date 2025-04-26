
rule Trojan_BAT_LummaStealer_PADI_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.PADI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 9a 00 00 00 61 d2 81 1a 00 00 01 03 50 06 8f 1a 00 00 01 25 71 1a 00 00 01 1f 40 58 d2 81 1a 00 00 01 03 50 06 8f 1a 00 00 01 25 71 1a 00 00 01 1f 43 59 d2 81 1a 00 00 01 03 50 06 8f 1a 00 00 01 25 71 1a 00 00 01 20 b8 00 00 00 58 d2 81 1a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}