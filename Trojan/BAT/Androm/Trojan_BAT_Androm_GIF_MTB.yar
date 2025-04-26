
rule Trojan_BAT_Androm_GIF_MTB{
	meta:
		description = "Trojan:BAT/Androm.GIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 07 2b 2f 00 08 6f ?? ?? ?? 0a 11 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 16 91 13 08 09 11 08 6f ?? ?? ?? 0a 00 00 11 07 18 58 13 07 11 07 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a fe 04 13 09 11 09 2d bc } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}