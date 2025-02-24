
rule Trojan_BAT_Vidar_AVI_MTB{
	meta:
		description = "Trojan:BAT/Vidar.AVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 00 25 06 6f ?? ?? ?? 0a 00 25 17 6f ?? ?? ?? 0a 00 25 16 6f ?? ?? ?? 0a 00 25 17 6f ?? ?? ?? 0a 00 25 17 6f ?? ?? ?? 0a 00 0b 07 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}