
rule Trojan_BAT_Heracles_AHA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 2b f5 07 08 18 5b 02 08 18 6f 39 00 00 0a 1f 10 28 8d 00 00 0a 9c 08 18 58 0c 08 06 32 e4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}