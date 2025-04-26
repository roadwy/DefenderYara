
rule Trojan_BAT_XWorm_AOX_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AOX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 11 04 1c 58 28 ?? 00 00 0a 13 0e 16 13 11 2b 75 03 11 0d 1f 0c 58 28 ?? 00 00 0a 13 12 03 11 0d 1f 10 58 28 ?? 00 00 0a 13 13 03 11 0d 1f 14 58 28 ?? 00 00 0a 13 14 11 13 2c 3d 11 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}