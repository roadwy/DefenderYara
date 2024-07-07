
rule Trojan_BAT_Vidar_PSLO_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PSLO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 3f 00 00 06 0a 06 28 5e 00 00 0a 7d 30 00 00 04 06 02 7d 32 00 00 04 06 03 7d 31 00 00 04 06 15 7d 2f 00 00 04 06 7c 30 00 00 04 12 00 28 03 00 00 2b 06 7c 30 00 00 04 28 60 00 00 0a 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}