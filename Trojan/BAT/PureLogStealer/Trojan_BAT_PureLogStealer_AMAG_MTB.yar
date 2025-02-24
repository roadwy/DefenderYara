
rule Trojan_BAT_PureLogStealer_AMAG_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AMAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {95 58 20 ff 00 00 00 5f 13 [0-14] 61 20 ff 00 00 00 5f 13 [0-14] 58 20 00 01 00 00 5e 13 [0-32] 95 61 28 ?? 00 00 0a 9c 11 ?? 17 58 13 ?? ?? ?? 07 8e 69 3f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}