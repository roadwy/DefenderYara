
rule Trojan_BAT_PureLogStealer_SXDA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.SXDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 d1 13 12 11 1c 11 09 91 13 22 11 1c 11 09 11 26 11 22 61 19 11 1b 58 61 11 32 61 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}