
rule Trojan_BAT_PureLogStealer_SZZB_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.SZZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 1f 10 8d 1a 00 00 01 25 d0 50 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 07 6f ?? 00 00 0a 17 73 57 00 00 0a 25 02 16 02 8e 69 6f ?? 00 00 0a 6f } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}