
rule Trojan_BAT_Zusy_PSXI_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSXI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 1c 00 00 0a 26 02 28 04 00 00 06 15 28 1b 00 00 0a 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}