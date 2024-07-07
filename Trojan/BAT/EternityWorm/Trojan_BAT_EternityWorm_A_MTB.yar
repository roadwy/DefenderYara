
rule Trojan_BAT_EternityWorm_A_MTB{
	meta:
		description = "Trojan:BAT/EternityWorm.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 25 16 20 90 01 02 00 00 28 90 01 02 00 06 a2 25 17 20 90 01 02 00 00 28 90 01 02 00 06 a2 14 14 14 28 90 01 02 00 06 28 90 01 01 00 00 0a 13 01 38 90 09 0f 00 04 14 20 90 01 02 00 00 28 90 01 01 02 00 06 18 8d 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}