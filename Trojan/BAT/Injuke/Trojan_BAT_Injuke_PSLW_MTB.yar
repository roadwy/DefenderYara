
rule Trojan_BAT_Injuke_PSLW_MTB{
	meta:
		description = "Trojan:BAT/Injuke.PSLW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 0b 00 00 06 0a 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 0c 00 00 06 75 0f 00 00 1b 73 ?? ?? ?? 0a 0b 28 04 00 00 2b 6f ?? ?? ?? 0a 0c 38 0e 00 00 00 08 6f ?? ?? ?? 0a 0d 07 09 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 2d ea } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}