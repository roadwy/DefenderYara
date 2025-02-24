
rule Trojan_BAT_Jalapeno_GNT_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 08 1a 8d ?? ?? ?? ?? 13 09 11 08 11 09 16 1a 6f ?? ?? ?? 0a 26 11 09 16 28 ?? ?? ?? 0a 13 0a 11 08 16 73 ?? ?? ?? 0a 13 0b 11 0b 06 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}