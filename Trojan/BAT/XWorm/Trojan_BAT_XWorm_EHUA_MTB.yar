
rule Trojan_BAT_XWorm_EHUA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.EHUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 06 09 06 8e 69 5d 1f 19 58 1f 19 59 91 08 09 08 8e 69 5d 1b 58 1b 58 1f 0b 58 1f 16 59 1c 58 1b 59 91 61 06 09 20 10 02 00 00 58 20 0f 02 00 00 59 19 59 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}