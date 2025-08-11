
rule Trojan_BAT_Lazy_GVC_MTB{
	meta:
		description = "Trojan:BAT/Lazy.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {13 0f 11 20 11 09 91 13 28 11 20 11 09 11 26 11 28 61 ?? ?? ?? 58 61 11 2d 61 d2 9c 11 28 13 1e ?? ?? ?? 58 13 09 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}