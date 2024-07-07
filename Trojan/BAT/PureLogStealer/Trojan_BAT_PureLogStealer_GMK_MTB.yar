
rule Trojan_BAT_PureLogStealer_GMK_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 0a 11 0a 20 90 01 04 28 90 01 03 06 28 90 01 03 0a 20 90 01 04 28 90 01 03 06 28 90 01 03 0a 6f 90 01 03 0a 13 0f 73 90 01 04 13 0b 11 07 73 90 01 04 13 0c 11 0c 11 0f 16 73 90 01 04 13 0d 11 0d 11 0b 6f 90 01 03 0a 11 0b 6f 90 01 03 0a 13 07 de 08 11 0d 6f 90 01 03 0a dc de 08 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}