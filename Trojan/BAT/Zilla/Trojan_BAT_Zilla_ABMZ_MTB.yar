
rule Trojan_BAT_Zilla_ABMZ_MTB{
	meta:
		description = "Trojan:BAT/Zilla.ABMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 08 11 14 11 08 11 14 91 07 11 14 20 00 04 00 00 5d 91 61 08 11 14 20 00 02 00 00 5d 91 61 11 06 18 62 61 11 07 17 62 61 03 11 14 03 8e 69 5d 91 61 03 11 14 18 58 03 8e 69 5d 91 61 7e ?? 00 00 04 11 14 1f 40 5d 91 61 7e ?? 00 00 04 11 14 1f 40 5d 91 61 d2 9c 11 14 18 5d 2d 1d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}