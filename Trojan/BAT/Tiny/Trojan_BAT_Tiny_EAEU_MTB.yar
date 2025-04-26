
rule Trojan_BAT_Tiny_EAEU_MTB{
	meta:
		description = "Trojan:BAT/Tiny.EAEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 06 07 02 07 91 03 07 03 6f ?? ?? ?? ?? ?? ?? ?? 00 00 0a 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d da } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}