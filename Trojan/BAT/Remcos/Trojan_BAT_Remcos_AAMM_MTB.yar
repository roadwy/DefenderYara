
rule Trojan_BAT_Remcos_AAMM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AAMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 16 07 1f 0f 1f 10 28 ?? 00 00 06 7e ?? 00 00 04 06 07 28 ?? 00 00 06 7e ?? 00 00 04 06 18 28 ?? 00 00 06 7e ?? 00 00 04 06 1b 28 ?? 00 00 06 7e ?? 00 00 04 06 28 ?? 00 00 06 0d 7e ?? 00 00 04 09 04 16 04 8e 69 28 ?? 00 00 06 2a } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}