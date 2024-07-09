
rule Trojan_BAT_AgentTesla_SPJG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPJG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 72 71 06 00 70 72 b1 00 00 70 6f ?? ?? ?? 0a 0b 73 ?? ?? ?? 0a 0c 16 0d 2b 23 00 07 09 18 6f 80 00 00 0a 20 03 02 00 00 28 81 00 00 0a 13 05 08 11 05 6f 82 00 00 0a 00 09 18 58 0d 00 09 07 6f 83 00 00 0a fe 04 13 06 11 06 2d ce } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}