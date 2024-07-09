
rule Trojan_BAT_Zusy_PTJB_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 25 00 00 0a 15 16 28 ?? 00 00 0a 0b 02 28 ?? 00 00 0a 07 17 9a 6f 27 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}