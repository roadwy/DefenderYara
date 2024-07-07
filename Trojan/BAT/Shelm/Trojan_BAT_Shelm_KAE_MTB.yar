
rule Trojan_BAT_Shelm_KAE_MTB{
	meta:
		description = "Trojan:BAT/Shelm.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 07 03 8e 69 fe 01 0d 09 2c 02 16 0b 06 08 02 08 8f 90 01 01 00 00 01 25 47 03 07 91 61 d2 25 13 04 52 11 04 9c 00 08 17 58 0c 08 02 8e 69 fe 04 13 05 11 05 2d cb 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}