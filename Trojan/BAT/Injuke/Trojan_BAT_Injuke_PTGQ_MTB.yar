
rule Trojan_BAT_Injuke_PTGQ_MTB{
	meta:
		description = "Trojan:BAT/Injuke.PTGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f6 09 28 ?? 00 00 0a 28 ?? 01 00 06 74 0a 00 00 1b 0a 06 75 0a 00 00 1b 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}