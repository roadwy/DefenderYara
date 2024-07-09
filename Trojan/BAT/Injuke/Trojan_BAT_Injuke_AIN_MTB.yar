
rule Trojan_BAT_Injuke_AIN_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 1d 00 00 00 09 6f ?? ?? ?? 0a 13 07 08 11 07 07 02 11 07 18 5a 18 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}