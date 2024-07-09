
rule Trojan_BAT_Growtopia_PTCE_MTB{
	meta:
		description = "Trojan:BAT/Growtopia.PTCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 19 00 00 70 a2 25 19 08 6f 02 00 00 06 a2 25 1a 72 31 00 00 70 a2 28 ?? 00 00 0a 6f 1e 00 00 0a 26 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}