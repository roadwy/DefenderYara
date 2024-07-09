
rule Trojan_BAT_SpySnake_SP_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 7b 25 00 00 04 08 6f ?? ?? ?? 0a 13 04 08 12 00 28 ?? ?? ?? 0a 6b 11 04 7b 3d 00 00 04 5a 69 12 00 28 ?? ?? ?? 0a 6b 11 04 7b 3e 00 00 04 5a 69 73 1e 00 00 0a 6f ?? ?? ?? 0a 00 08 12 00 28 ?? ?? ?? 0a 6b 11 04 7b 3f 00 00 04 5a 69 12 00 28 ?? ?? ?? 0a 6b 11 04 7b 40 00 00 04 5a 69 73 21 00 00 0a 6f ?? ?? ?? 0a 00 00 00 07 6f ?? ?? ?? 0a 3a 6b ff ff ff } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}