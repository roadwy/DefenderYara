
rule Trojan_BAT_JesterStealer_AVEA_MTB{
	meta:
		description = "Trojan:BAT/JesterStealer.AVEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 5d 7e ?? 00 00 04 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 06 02 08 17 58 02 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}