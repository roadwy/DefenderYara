
rule Trojan_BAT_Heracles_ZDQ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ZDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 02 16 28 ?? 00 00 0a 13 03 38 ?? 00 00 00 11 03 16 3c ?? ff ff ff 38 ?? ff ff ff 11 00 11 02 16 1a 6f ?? 00 00 0a 1a 3b ?? ff ff ff 38 ?? ff ff ff 00 20 00 10 00 00 8d ?? 00 00 01 13 05 } //6
		$a_03_1 = {11 04 11 05 16 11 05 8e 69 6f ?? 00 00 0a 25 13 06 16 3d ?? 00 00 00 38 ?? 00 00 00 38 ?? ff ff ff 38 ?? 00 00 00 11 01 11 05 16 11 06 6f ?? 00 00 0a 38 } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}