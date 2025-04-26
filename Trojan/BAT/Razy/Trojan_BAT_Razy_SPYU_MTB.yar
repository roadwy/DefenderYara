
rule Trojan_BAT_Razy_SPYU_MTB{
	meta:
		description = "Trojan:BAT/Razy.SPYU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 02 16 02 8e 69 6f ?? ?? ?? 0a 00 11 04 6f ?? ?? ?? 0a 00 00 dd 17 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}