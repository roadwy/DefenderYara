
rule Trojan_BAT_Heracles_SPAP_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SPAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 9a 0d 09 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 2c 11 09 20 80 00 00 00 28 ?? ?? ?? 0a 09 28 ?? ?? ?? 0a 08 17 58 0c 08 07 8e 69 32 ca } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}