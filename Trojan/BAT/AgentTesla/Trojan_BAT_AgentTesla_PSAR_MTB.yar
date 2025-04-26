
rule Trojan_BAT_AgentTesla_PSAR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 12 05 28 21 ?? ?? ?? 07 09 18 6f 22 ?? ?? ?? 06 28 23 ?? ?? ?? 13 06 08 09 11 06 6f 24 ?? ?? ?? de 0c } //5
		$a_01_1 = {09 07 6f 26 00 00 0a 32 aa 08 6f 27 00 00 0a 28 01 00 00 2b 2a 0a 38 71 ff ff ff 28 09 00 00 06 38 71 ff ff ff 0b 38 70 ff ff ff 73 29 00 00 0a 38 6b ff ff ff 0c } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}