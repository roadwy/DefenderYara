
rule Trojan_BAT_PureLogStealer_SWA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 04 00 00 06 25 73 0a 00 00 06 6f ?? 00 00 06 25 73 0c 00 00 06 6f ?? 00 00 06 25 73 0e 00 00 06 6f ?? 00 00 06 25 73 10 00 00 06 6f ?? 00 00 06 6f ?? 00 00 06 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}