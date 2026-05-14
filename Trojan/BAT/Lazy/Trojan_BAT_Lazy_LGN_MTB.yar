
rule Trojan_BAT_Lazy_LGN_MTB{
	meta:
		description = "Trojan:BAT/Lazy.LGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 07 03 07 91 02 7b ?? 00 00 04 06 91 61 d2 9c 06 17 58 02 7b ?? 00 00 04 8e 69 5d 0a 00 07 17 58 0b 07 03 8e 69 fe 04 0c 08 2d d3 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}