
rule Trojan_BAT_SalatStealer_APRB_MTB{
	meta:
		description = "Trojan:BAT/SalatStealer.APRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 17 58 20 00 01 00 00 5d 0d 08 07 09 94 58 20 00 01 00 00 5d 0c 07 09 94 13 08 07 09 07 08 94 9e 07 08 11 08 9e 06 11 07 02 11 07 91 07 07 09 94 07 08 94 58 20 00 01 00 00 5d 94 61 d2 9c 11 07 17 58 13 07 11 07 02 8e 69 32 b4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}