
rule Trojan_BAT_Injuke_NFAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.NFAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 03 06 58 47 04 06 04 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 06 17 58 0a 06 02 8e 69 32 df } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}