
rule Trojan_BAT_XWorm_AXO_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AXO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 0a 2b 2b 11 05 11 0a 8f 15 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_XWorm_AXO_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.AXO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 16 13 04 02 28 ?? 00 00 0a 0c 08 13 08 16 13 07 2b 3a 11 08 11 07 91 13 06 11 06 09 11 04 6f ?? 00 00 0a 28 ?? 00 00 0a 61 b4 28 ?? 00 00 0a 13 05 06 11 05 6f ?? 00 00 0a 11 04 17 d6 09 6f } //3
		$a_03_1 = {61 b4 13 05 06 11 05 6f ?? 00 00 0a 09 17 d6 08 6f ?? 00 00 0a 5d 0d 11 06 17 d6 13 06 11 06 11 08 32 bf } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}