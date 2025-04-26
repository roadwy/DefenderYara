
rule Trojan_BAT_PureLogStealer_SPZF_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.SPZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 16 11 19 11 09 91 13 28 11 19 11 09 11 20 11 28 61 11 18 19 58 61 11 32 61 d2 9c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}