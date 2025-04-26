
rule Trojan_BAT_Nanocore_AAEF_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AAEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 01 02 8e 69 5d 02 11 01 02 8e 69 5d 91 11 00 11 01 11 00 8e 69 5d 91 61 28 ?? 00 00 06 02 11 01 17 58 02 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 0a 9c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}