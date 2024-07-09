
rule Trojan_BAT_Stealer_AAYD_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AAYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 09 06 8e 69 5d 06 09 06 8e 69 5d 91 08 09 08 8e 69 5d 91 61 28 ?? 00 00 0a 06 09 17 58 06 8e 69 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 09 17 58 0d 09 6a 06 8e 69 17 59 6a 07 17 58 6e 5a 31 bb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}