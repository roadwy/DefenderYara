
rule Trojan_BAT_Scrami_GZZ_MTB{
	meta:
		description = "Trojan:BAT/Scrami.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 12 1e 1f 40 12 15 28 ?? 00 00 06 26 1e 8d 47 00 00 01 16 11 12 28 ?? 00 00 0a 1e 28 ?? 00 00 0a 11 12 1f 28 58 13 12 11 1f 17 58 13 1f 11 1f 11 13 32 cc 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}