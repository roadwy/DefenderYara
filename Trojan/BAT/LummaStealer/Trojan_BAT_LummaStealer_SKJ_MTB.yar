
rule Trojan_BAT_LummaStealer_SKJ_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.SKJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 0f 00 00 0a 72 01 00 00 70 28 10 00 00 0a 6f 11 00 00 0a 0a 28 0f 00 00 0a 72 33 00 00 70 28 10 00 00 0a 6f 11 00 00 0a 0b 73 12 00 00 0a 25 6f 13 00 00 0a 06 07 6f 14 00 00 0a 7e 01 00 00 04 6f 15 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}