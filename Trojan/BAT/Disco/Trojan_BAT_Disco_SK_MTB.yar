
rule Trojan_BAT_Disco_SK_MTB{
	meta:
		description = "Trojan:BAT/Disco.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 07 09 07 8e 69 5d 02 07 09 07 8e 69 5d 91 08 09 08 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a d2 07 09 17 58 07 8e 69 5d 91 28 ?? ?? ?? 0a d2 59 20 00 01 00 00 58 28 ?? ?? ?? 06 28 ?? ?? ?? 0a d2 9c 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 07 11 07 2d a8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}