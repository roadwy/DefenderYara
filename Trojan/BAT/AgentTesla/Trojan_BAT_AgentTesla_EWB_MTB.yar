
rule Trojan_BAT_AgentTesla_EWB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0e 04 0b 07 17 2e 06 07 18 2e 0a 2b 2d 02 03 5d 0c 08 0a 2b 27 } //1
		$a_01_1 = {41 00 53 00 41 00 4d 00 65 00 74 00 68 00 6f 00 64 00 30 00 41 00 53 00 41 00 } //1 ASAMethod0ASA
		$a_01_2 = {21 00 4d 00 21 00 65 00 21 00 74 00 21 00 68 00 21 00 6f 00 21 00 64 00 21 00 30 00 21 00 } //1 !M!e!t!h!o!d!0!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}