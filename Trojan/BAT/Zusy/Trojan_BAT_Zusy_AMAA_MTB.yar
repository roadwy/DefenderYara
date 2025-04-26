
rule Trojan_BAT_Zusy_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 07 17 73 ?? 00 00 0a 0d 28 [0-1e] 00 00 0a 09 6f ?? 00 00 0a 08 6f ?? 00 00 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}