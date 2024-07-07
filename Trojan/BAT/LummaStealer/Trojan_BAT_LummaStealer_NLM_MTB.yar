
rule Trojan_BAT_LummaStealer_NLM_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.NLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 14 72 5f 29 00 70 16 8d 90 01 02 00 01 14 14 14 28 90 01 02 00 0a 28 39 00 00 0a 13 05 11 04 11 05 28 90 01 02 00 0a 6f 34 01 00 0a 00 11 0c 11 0b 12 0c 28 90 01 02 00 0a 13 0e 11 0e 2d c4 11 04 6f 90 01 02 00 0a 28 08 00 00 2b 90 00 } //3
		$a_03_1 = {28 d0 00 00 0a 14 72 90 01 02 00 70 17 8d 90 01 02 00 01 25 16 72 00 24 00 70 a2 14 90 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}