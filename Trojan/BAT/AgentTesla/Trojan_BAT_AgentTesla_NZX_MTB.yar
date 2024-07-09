
rule Trojan_BAT_AgentTesla_NZX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 11 0d 16 11 0b 6f ?? ?? ?? 0a 25 26 26 11 0a 11 0d 16 11 0b 11 0c 16 6f ?? ?? ?? 0a 25 26 13 0f } //1
		$a_01_1 = {54 00 6b 00 4a 00 6f 00 53 00 47 00 68 00 49 00 53 00 45 00 67 00 6b 00 } //1 TkJoSGhISEgk
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}