
rule Trojan_BAT_Darkrat_EARS_MTB{
	meta:
		description = "Trojan:BAT/Darkrat.EARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {d2 61 d2 9c 08 09 8f 16 00 00 01 25 47 07 09 07 8e 69 5d 91 61 d2 52 09 17 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}