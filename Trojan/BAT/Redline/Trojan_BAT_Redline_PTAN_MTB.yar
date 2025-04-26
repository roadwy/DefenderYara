
rule Trojan_BAT_Redline_PTAN_MTB{
	meta:
		description = "Trojan:BAT/Redline.PTAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 39 01 00 0a 17 73 27 01 00 0a 0c 08 02 16 02 8e 69 6f 3a 01 00 0a 08 6f 3b 01 00 0a 06 28 ?? 01 00 06 0d 28 ?? 01 00 06 09 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}