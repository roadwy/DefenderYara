
rule Trojan_BAT_AgentTesla_DYF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 6c 23 ff b9 f4 ee 2a 81 f7 3f 5b 28 ?? ?? ?? 0a b7 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 07 0a } //1
		$a_01_1 = {42 00 75 00 2d 00 6e 00 69 00 2d 00 2d 00 66 00 75 00 5f 00 54 00 2d 00 2d 00 65 00 78 00 2d 00 2d 00 74 00 42 00 6f 00 2d 00 2d 00 2d 00 78 00 } //1 Bu-ni--fu_T--ex--tBo---x
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}