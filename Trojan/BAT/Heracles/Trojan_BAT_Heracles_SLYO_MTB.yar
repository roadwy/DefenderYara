
rule Trojan_BAT_Heracles_SLYO_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SLYO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 16 9a 28 1b 00 00 06 0a 02 7b ?? 00 00 04 26 02 06 28 14 00 00 06 02 7b ?? 00 00 04 26 02 02 7b ?? 00 00 04 2d 03 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}