
rule Trojan_BAT_AgentTesla_LLD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LLD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 00 00 fe 0c 01 00 fe 09 00 00 fe 0c 01 00 91 fe 09 01 00 fe 0c 01 00 fe 09 01 00 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 9c fe 0c 01 00 20 01 00 00 00 58 fe 0e 01 00 fe 0c 01 00 fe 09 00 00 8e 69 20 01 00 00 00 59 fe 02 20 00 00 00 00 fe 01 fe 0e 02 00 fe 0c 02 00 3a 98 ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}