
rule Trojan_BAT_Poison_PSOT_MTB{
	meta:
		description = "Trojan:BAT/Poison.PSOT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 0b 00 00 06 0a 28 0b 00 00 0a 06 6f 0c 00 00 0a 28 0a 00 00 06 75 01 00 00 1b 0b 07 16 07 8e 69 28 0d 00 00 0a 07 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}