
rule Trojan_BAT_AgentTesla_NSU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {6b 6c 68 6a 66 70 6f 5b 6a 68 66 66 73 64 61 72 74 75 6c 75 70 6f 70 6f 68 67 74 72 73 72 74 79 74 79 75 69 5b 5d 7a 78 63 76 6a 68 75 37 79 67 6f 70 } //1 klhjfpo[jhffsdartulupopohgtrsrtytyui[]zxcvjhu7ygop
		$a_81_1 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 2e 41 73 73 65 6d 62 6c 79 } //1 System.Reflection.Assembly
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}