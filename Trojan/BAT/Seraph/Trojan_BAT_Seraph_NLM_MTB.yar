
rule Trojan_BAT_Seraph_NLM_MTB{
	meta:
		description = "Trojan:BAT/Seraph.NLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 7b 0a 00 00 04 6f ?? ?? ?? 0a 2d 55 28 ?? ?? ?? 0a 07 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0d 06 1a 58 16 54 2b 2c } //5
		$a_01_1 = {4a 65 70 65 73 62 72 79 71 70 68 } //1 Jepesbryqph
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}