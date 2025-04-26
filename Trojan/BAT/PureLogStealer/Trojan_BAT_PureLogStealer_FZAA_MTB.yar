
rule Trojan_BAT_PureLogStealer_FZAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.FZAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0c 17 0d 2b 08 08 09 58 0c 09 17 58 0d 19 2c c9 1c 2c ec 09 02 31 ee } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}