
rule Trojan_BAT_Heracles_DV_MTB{
	meta:
		description = "Trojan:BAT/Heracles.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 08 00 00 00 64 d2 9c fe 0c 07 00 fe 0c 05 00 25 20 01 00 00 00 58 fe 0e 05 00 fe 0c 0b 00 20 10 00 00 00 64 d2 9c fe 0c 07 00 fe 0c 05 00 25 20 01 00 00 00 58 fe 0e 05 00 fe 0c 0b 00 20 18 00 00 00 64 d2 9c fe 0c 02 00 fe 0c 0a 00 8f 40 00 00 01 25 4b fe 0c 0b 00 61 54 fe 0c 0a 00 20 01 00 00 00 58 fe 0e 0a 00 fe 0c 0a 00 20 10 00 00 00 3f 4c ff ff ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}