
rule Trojan_BAT_LummaStealer_AAFK_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.AAFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 25 08 28 ?? 00 00 06 25 17 28 ?? 00 00 06 25 18 28 ?? 00 00 06 25 06 28 ?? 00 00 06 28 ?? 00 00 06 07 16 07 8e 69 28 ?? 00 00 06 0d 20 ?? 00 00 00 38 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}