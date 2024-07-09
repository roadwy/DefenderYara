
rule Trojan_BAT_AgentTesla_NNT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 7c 05 00 0a 13 06 11 06 07 16 07 8e 69 6f ?? ?? 00 0a 11 06 6f ?? ?? 00 0a 11 04 6f ?? ?? 00 0a 28 ?? ?? 00 0a } //5
		$a_01_1 = {4d 47 2e 4f 66 66 69 63 65 2e 45 64 69 74 6f 72 2e 66 72 6d 44 65 62 75 67 2e 72 65 73 6f 75 72 63 65 73 } //1 MG.Office.Editor.frmDebug.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}