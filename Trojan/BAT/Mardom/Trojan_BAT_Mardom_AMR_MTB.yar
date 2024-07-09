
rule Trojan_BAT_Mardom_AMR_MTB{
	meta:
		description = "Trojan:BAT/Mardom.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 0b 2b 13 09 07 9a 03 28 ?? ?? ?? 06 13 04 11 04 2d 0c 07 17 58 0b 07 09 8e 69 32 e7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}