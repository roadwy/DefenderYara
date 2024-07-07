
rule Trojan_BAT_Coins_KAA_MTB{
	meta:
		description = "Trojan:BAT/Coins.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 fe 0c 01 00 fe 0c 02 00 fe 09 00 00 fe 0c 02 00 6f 90 01 01 00 00 0a fe 0c 00 00 fe 0c 02 00 fe 0c 00 00 8e 69 5d 91 61 d2 9c 00 fe 0c 02 00 20 90 01 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 09 00 00 6f 90 01 01 00 00 0a fe 04 fe 0e 03 00 fe 0c 03 00 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}