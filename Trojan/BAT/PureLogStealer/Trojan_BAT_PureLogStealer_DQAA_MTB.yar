
rule Trojan_BAT_PureLogStealer_DQAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.DQAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {09 d3 07 58 11 04 d3 06 58 47 52 08 16 fe 01 13 0d 11 0d 2d 23 00 09 d3 07 58 09 d3 07 58 47 1a 63 d2 52 09 d3 07 58 25 47 11 04 d3 06 17 58 58 47 1a 62 d2 58 d2 52 } //01 00 
		$a_01_1 = {56 00 6d 00 4c 00 6f 00 61 00 64 00 } //00 00  VmLoad
	condition:
		any of ($a_*)
 
}