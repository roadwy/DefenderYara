
rule Trojan_BAT_AgentTesla_CSST_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CSST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 0b 00 00 06 0a 28 0b 00 00 0a 06 6f 0c 00 00 0a 28 0a 00 00 06 75 01 00 00 1b 0b 07 16 07 8e 69 28 ?? ?? ?? ?? 07 2a } //5
		$a_03_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 62 00 6c 00 6f 00 63 00 65 00 78 00 70 00 65 00 72 00 74 00 2e 00 65 00 75 00 2f 00 2e 00 77 00 65 00 6c 00 6c 00 2d 00 6b 00 6e 00 6f 00 77 00 6e 00 2f [0-1f] 2e 00 70 00 6e 00 67 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}