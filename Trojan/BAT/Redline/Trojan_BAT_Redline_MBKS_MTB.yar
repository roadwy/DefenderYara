
rule Trojan_BAT_Redline_MBKS_MTB{
	meta:
		description = "Trojan:BAT/Redline.MBKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 02 8e 69 5d 7e ?? 00 00 04 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 06 02 08 20 8e 10 00 00 58 20 8d 10 00 00 59 02 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}