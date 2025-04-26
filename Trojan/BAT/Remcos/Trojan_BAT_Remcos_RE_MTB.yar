
rule Trojan_BAT_Remcos_RE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 13 26 2b 67 2b 6b 72 ?? 00 00 70 6f ?? 00 00 0a 2c 07 2b 03 0c 2b eb 08 2a 07 17 58 17 2c fb 0b 07 06 8e 69 1e 2c f4 32 ca 16 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}