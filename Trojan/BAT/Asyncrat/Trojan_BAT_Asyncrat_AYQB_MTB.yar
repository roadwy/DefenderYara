
rule Trojan_BAT_Asyncrat_AYQB_MTB{
	meta:
		description = "Trojan:BAT/Asyncrat.AYQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 0b 2b 1e 00 11 0a 11 0b 11 08 11 0b 91 11 09 11 0b 11 09 8e 69 5d 91 61 d2 9c 00 11 0b 17 58 13 0b 11 0b 11 08 8e 69 fe 04 13 0e 11 0e 2d d4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}