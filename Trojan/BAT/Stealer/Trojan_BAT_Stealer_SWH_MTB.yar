
rule Trojan_BAT_Stealer_SWH_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 b8 05 00 06 28 b7 05 00 06 0d 28 ?? ?? ?? 0a 28 b9 05 00 06 28 b7 05 00 06 28 15 00 00 0a 13 04 73 ?? ?? ?? 0a 13 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}