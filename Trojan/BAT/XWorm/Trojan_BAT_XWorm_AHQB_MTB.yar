
rule Trojan_BAT_XWorm_AHQB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AHQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 8e 69 18 da 0b 73 ?? ?? 00 0a 0c 73 ?? ?? 00 0a 0d 07 13 04 16 13 05 2b 1e 03 11 05 9a 28 ?? ?? 00 0a 1f 7c da b4 13 06 09 11 06 6f ?? ?? 00 0a 00 11 05 17 d6 13 05 11 05 11 04 31 dc 08 09 6f ?? ?? 00 0a 00 08 6f ?? ?? 00 0a 0a 2b 00 06 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}