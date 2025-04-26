
rule Trojan_BAT_AgentTesla_CNL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 15 00 00 06 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 0a de 03 } //5
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 36 30 2e 50 72 6f 70 65 72 74 69 65 73 } //1 WindowsFormsApp60.Properties
		$a_01_2 = {4f 66 6b 7a 6d 6c 75 63 77 61 6c } //1 Ofkzmlucwal
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}