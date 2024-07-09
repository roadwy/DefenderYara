
rule Trojan_BAT_AgentTesla_ABMG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 07 11 0a 11 06 11 0a 9a 1f 10 28 ?? ?? ?? 0a d2 9c 11 0a 17 58 13 0a 11 0a 11 06 8e 69 fe 04 13 0b 11 0b 2d da } //4
		$a_01_1 = {41 00 6d 00 69 00 72 00 43 00 61 00 6c 00 65 00 6e 00 64 00 61 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 43 00 6f 00 6d 00 62 00 6f 00 } //1 AmirCalendar.ResourceCombo
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}