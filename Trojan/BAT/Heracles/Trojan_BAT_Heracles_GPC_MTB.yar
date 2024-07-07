
rule Trojan_BAT_Heracles_GPC_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 8d 19 00 00 01 0a 16 0b 2b 15 00 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}