
rule Trojan_BAT_XWorm_SXB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 08 02 7b 0c 00 00 04 20 00 01 00 00 14 09 28 ?? 00 00 0a 02 7b 0d 00 00 04 6f ?? 00 00 0a 26 11 05 17 d6 13 05 11 05 11 06 8e b7 32 9c } //20
		$a_03_1 = {16 33 09 02 14 7d ?? 00 00 04 de 36 02 03 28 ?? 00 00 0a 7d ?? 00 00 04 02 7b ?? 00 00 04 2d 0b } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}