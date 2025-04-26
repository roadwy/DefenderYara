
rule Trojan_BAT_Remcos_AAMT_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AAMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 1a 58 4a 03 8e 69 5d 03 06 1a 58 4a 03 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? 00 00 0a 03 06 1a 58 4a 1b 58 1a 59 03 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}