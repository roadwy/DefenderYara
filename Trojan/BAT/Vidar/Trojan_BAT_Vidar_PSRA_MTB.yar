
rule Trojan_BAT_Vidar_PSRA_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PSRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 11 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 03 38 41 00 00 00 02 1f 10 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 00 20 01 00 00 00 28 ?? ?? ?? 06 3a 27 ff ff ff } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}