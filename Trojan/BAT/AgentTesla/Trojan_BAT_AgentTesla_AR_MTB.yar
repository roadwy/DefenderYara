
rule Trojan_BAT_AgentTesla_AR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {06 08 8f 05 ?? ?? 01 25 47 02 08 1f 10 5d 91 61 d2 52 08 17 d6 0c 08 07 fe 02 16 fe 01 0d 09 2d df } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}