
rule Trojan_BAT_Injuke_JGAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.JGAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 09 07 09 91 20 ?? ?? 00 00 28 ?? 08 00 06 28 ?? 00 00 0a 59 d2 9c 09 17 58 0d 09 07 8e 69 32 df } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}