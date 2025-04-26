
rule Trojan_BAT_Cobaltstrike_PTIQ_MTB{
	meta:
		description = "Trojan:BAT/Cobaltstrike.PTIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 10 00 00 1f 40 28 ?? 00 00 06 0a 03 16 06 03 8e 69 28 ?? 00 00 0a 06 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}