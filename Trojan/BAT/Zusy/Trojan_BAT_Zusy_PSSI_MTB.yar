
rule Trojan_BAT_Zusy_PSSI_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSSI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 18 00 00 0a 6f ?? 00 00 0a 07 72 c9 00 00 70 73 1a 00 00 0a 08 6f ?? 00 00 0a 06 7b 05 00 00 04 6f ?? 00 00 0a 26 08 28 ?? 00 00 0a 2d 57 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}