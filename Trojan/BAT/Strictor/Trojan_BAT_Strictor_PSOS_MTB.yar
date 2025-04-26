
rule Trojan_BAT_Strictor_PSOS_MTB{
	meta:
		description = "Trojan:BAT/Strictor.PSOS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 28 39 00 00 0a 03 6f 3a 00 00 0a 0a 06 28 3b 00 00 0a 0b 07 0c 2b 00 08 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}