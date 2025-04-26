
rule Trojan_BAT_SmokeLoader_GFT_MTB{
	meta:
		description = "Trojan:BAT/SmokeLoader.GFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 1d 2d 1c 26 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 19 2d 06 26 de 09 0a 2b e2 0b 2b f8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}