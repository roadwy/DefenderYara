
rule Trojan_BAT_Searaph_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Searaph.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 08 06 1a 58 4a 08 8e 69 5d 91 07 06 1a 58 4a 91 61 d2 6f ?? 00 00 0a 06 1a 58 06 1a 58 4a 17 58 54 06 1a 58 4a 07 8e 69 32 d5 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}