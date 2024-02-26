
rule Trojan_BAT_AgentTesla_MBEZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 11 08 91 08 11 09 91 61 20 00 01 00 00 13 0b 07 11 0a 91 59 11 0b 58 11 0b 5d 13 0c 11 0d } //01 00 
		$a_01_1 = {54 69 6e 79 41 6c 65 72 74 45 78 61 6d 70 6c 65 2e 50 72 6f 70 65 } //00 00  TinyAlertExample.Prope
	condition:
		any of ($a_*)
 
}