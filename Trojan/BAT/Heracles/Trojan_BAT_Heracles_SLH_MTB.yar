
rule Trojan_BAT_Heracles_SLH_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SLH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {26 07 08 6f 29 00 00 06 16 6a 0d 16 13 06 2b 1d 06 6f 2f 00 00 0a 13 07 09 11 07 d2 6e 1e 11 06 5a 1f 3f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}