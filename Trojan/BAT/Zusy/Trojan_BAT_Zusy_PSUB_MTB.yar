
rule Trojan_BAT_Zusy_PSUB_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSUB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 12 00 00 0a 72 01 00 00 70 72 47 00 00 70 6f ?? 00 00 0a 72 47 00 00 70 28 ?? 00 00 0a 26 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}