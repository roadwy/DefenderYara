
rule Trojan_BAT_PureLogStealer_SPGF_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.SPGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 04 11 04 16 32 08 08 11 04 6f ?? 00 00 0a 09 18 58 0d 09 07 6f ?? 00 00 0a 32 d5 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}