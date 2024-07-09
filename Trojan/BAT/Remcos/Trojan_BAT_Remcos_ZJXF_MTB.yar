
rule Trojan_BAT_Remcos_ZJXF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZJXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 06 00 00 04 73 48 00 00 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 07 00 00 1b 0a 06 28 14 00 00 06 0b 07 72 ?? ?? ?? 70 28 15 00 00 06 74 93 00 00 01 6f 4a 00 00 0a 1f 0b 9a 80 05 00 00 04 23 20 6d 4e eb 57 0a 18 40 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}