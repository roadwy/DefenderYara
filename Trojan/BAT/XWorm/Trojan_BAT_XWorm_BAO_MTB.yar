
rule Trojan_BAT_XWorm_BAO_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 00 73 86 01 00 0a 0d 00 09 08 17 73 87 01 00 0a 13 05 11 05 02 16 02 8e 69 ?? ?? ?? 00 0a 00 11 05 ?? ?? ?? 00 0a 00 de 0e 00 11 05 2c 08 11 05 ?? ?? 00 00 0a 00 dc 09 13 04 11 04 0a de 0c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}