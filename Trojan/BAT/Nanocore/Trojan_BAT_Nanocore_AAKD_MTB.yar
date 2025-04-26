
rule Trojan_BAT_Nanocore_AAKD_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AAKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 08 8e 69 5d 13 06 08 11 06 91 13 07 09 11 05 1f 16 5d 6f ?? 00 00 0a d2 13 08 08 11 05 17 58 08 8e 69 5d 91 13 09 11 07 11 08 61 11 09 20 00 01 00 00 58 20 00 01 00 00 5d 59 13 0a 08 11 06 11 0a d2 9c 00 11 05 17 59 13 05 11 05 16 fe 04 16 fe 01 13 0b 11 0b 2d a5 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}