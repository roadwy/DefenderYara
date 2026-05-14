
rule Trojan_BAT_Heracles_SXD_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 0f 8d 07 00 00 01 25 d0 01 00 00 04 28 ?? 00 00 0a 0d 07 09 8e 69 6a 28 ?? 00 00 0a 1f 40 12 02 28 ?? 00 00 06 26 09 16 07 09 8e 69 28 ?? 00 00 0a 07 09 8e 69 6a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}