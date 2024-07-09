
rule Trojan_BAT_AgentTesla_SPAZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 08 2b 0d 2b 12 2b 17 de 1b 28 ?? ?? ?? 06 2b f1 28 ?? ?? ?? 2b 2b ec 28 ?? ?? ?? 2b 2b e7 0a 2b e6 } //3
		$a_01_1 = {59 00 63 00 78 00 75 00 62 00 6d 00 70 00 63 00 6d 00 69 00 63 00 75 00 63 00 71 00 68 00 } //1 Ycxubmpcmicucqh
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}