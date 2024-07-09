
rule Trojan_BAT_AgentTesla_NTQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 00 00 fe 0c 03 00 6f ?? ?? ?? 0a fe 0e 02 00 fe 0c 02 00 20 ?? 00 00 00 61 d1 fe 0e 02 00 fe 0c 01 00 fe 0c 02 00 6f ?? ?? ?? 0a 26 fe 0c 03 00 20 ?? 00 00 00 58 fe 0e 03 00 fe 0c 03 00 fe 09 00 00 6f ?? ?? ?? 0a 3f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}