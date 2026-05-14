
rule Trojan_BAT_XWorm_BAR_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 12 00 00 0a 0c 08 06 ?? ?? 00 00 0a 17 73 14 00 00 0a 0d 09 02 16 02 8e 69 ?? ?? 00 00 0a de 0a 09 2c 06 09 ?? ?? 00 00 0a dc 08 ?? ?? 00 00 0a 13 04 de 14 } //2
		$a_81_1 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}