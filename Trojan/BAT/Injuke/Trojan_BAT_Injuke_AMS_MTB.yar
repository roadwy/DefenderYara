
rule Trojan_BAT_Injuke_AMS_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 05 11 1f 9a 1f 10 28 ?? 00 00 0a 86 6f ?? 00 00 0a 00 11 1f 17 d6 13 1f 11 1f 11 1e 31 df } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}