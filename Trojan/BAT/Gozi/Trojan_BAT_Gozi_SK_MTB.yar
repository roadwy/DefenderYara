
rule Trojan_BAT_Gozi_SK_MTB{
	meta:
		description = "Trojan:BAT/Gozi.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 08 02 8e 69 5d 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 35 00 00 0a 02 08 17 58 02 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 31 b9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}