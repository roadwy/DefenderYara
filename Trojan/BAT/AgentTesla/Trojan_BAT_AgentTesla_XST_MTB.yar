
rule Trojan_BAT_AgentTesla_XST_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.XST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 07 08 9a 1f 10 28 ?? ?? ?? 0a d2 9c 08 17 58 0c 08 06 8e 69 32 e8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}