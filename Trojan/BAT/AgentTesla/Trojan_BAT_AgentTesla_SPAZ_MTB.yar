
rule Trojan_BAT_AgentTesla_SPAZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {2b 08 2b 0d 2b 12 2b 17 de 1b 28 90 01 03 06 2b f1 28 90 01 03 2b 2b ec 28 90 01 03 2b 2b e7 0a 2b e6 90 00 } //01 00 
		$a_01_1 = {59 00 63 00 78 00 75 00 62 00 6d 00 70 00 63 00 6d 00 69 00 63 00 75 00 63 00 71 00 68 00 } //00 00  Ycxubmpcmicucqh
	condition:
		any of ($a_*)
 
}