
rule Trojan_BAT_LummaStealer_GC_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 f2 00 00 70 28 2a 00 00 0a 0a 06 8e 69 0b 2b 0f 06 07 06 07 93 20 76 00 00 00 61 02 61 d1 9d 07 17 59 25 0b 16 2f e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}