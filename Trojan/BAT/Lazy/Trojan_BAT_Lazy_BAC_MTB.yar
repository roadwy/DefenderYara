
rule Trojan_BAT_Lazy_BAC_MTB{
	meta:
		description = "Trojan:BAT/Lazy.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 08 02 16 02 8e 69 ?? ?? 00 00 0a 00 08 ?? ?? 00 00 0a 00 07 ?? ?? 00 00 0a 0d de 36 08 14 fe 01 13 04 11 04 2d 07 08 ?? ?? 00 00 0a 00 dc 07 14 fe 01 13 04 11 04 2d 07 07 ?? ?? 00 00 0a 00 dc 06 14 fe 01 13 04 11 04 2d 07 06 } //2
		$a_81_1 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}