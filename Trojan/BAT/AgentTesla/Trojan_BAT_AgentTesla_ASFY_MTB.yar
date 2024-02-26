
rule Trojan_BAT_AgentTesla_ASFY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 11 06 91 20 00 01 00 00 13 09 08 11 07 91 61 07 11 08 91 59 11 09 58 11 09 5d 13 0a 07 11 06 11 0a d2 9c } //01 00 
		$a_01_1 = {11 05 1f 16 5d 13 07 11 05 17 58 11 04 5d 13 08 } //00 00  ԑᘟ፝ᄇᜅᅘ崄ࠓ
	condition:
		any of ($a_*)
 
}