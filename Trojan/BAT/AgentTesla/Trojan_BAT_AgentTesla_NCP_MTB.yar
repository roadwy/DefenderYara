
rule Trojan_BAT_AgentTesla_NCP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 6f ?? ?? ?? 0a 03 07 1f 10 5d 91 61 07 20 ff 00 00 00 5d d1 61 d1 9d 07 17 58 0b 07 02 6f 20 00 00 0a 32 d8 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}