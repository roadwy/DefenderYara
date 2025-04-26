
rule Trojan_BAT_AgentTesla_RDBB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 02 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 0d 09 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}