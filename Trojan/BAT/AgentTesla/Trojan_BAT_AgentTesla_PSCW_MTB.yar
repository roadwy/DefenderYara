
rule Trojan_BAT_AgentTesla_PSCW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 04 00 00 06 73 18 00 00 0a 0b 73 14 00 00 0a 0c 07 16 73 19 00 00 0a 73 1a 00 00 0a 0d 09 08 6f 16 00 00 0a de 0a } //5
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_2 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}