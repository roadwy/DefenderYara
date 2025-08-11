
rule Trojan_BAT_PureLogStealer_AFRA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AFRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 06 8e 69 40 02 00 00 00 16 0d 08 11 04 07 11 04 91 06 09 93 7e ?? ?? 00 04 28 ?? ?? 00 06 61 d2 9c 09 17 58 0d 11 04 17 58 13 04 11 04 07 8e 69 3f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}