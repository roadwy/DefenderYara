
rule Trojan_BAT_PureLogStealer_SSGL_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.SSGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 02 04 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 06 03 04 17 58 20 ?? ?? ?? 00 5d 91 28 ?? ?? ?? 06 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 06 9c 03 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}