
rule Trojan_BAT_XWorm_BAE_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 73 09 00 00 0a 13 09 11 09 11 08 16 73 0a 00 00 0a 13 0a 73 0b 00 00 0a 13 0b 00 11 0a 11 0b ?? ?? 00 00 0a 00 11 0b ?? ?? 00 00 0a 0d 00 de 0d 11 0b 2c 08 11 0b ?? ?? 00 00 0a 00 dc de 0d 11 0a 2c 08 11 0a ?? ?? 00 00 0a 00 dc de 0d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}