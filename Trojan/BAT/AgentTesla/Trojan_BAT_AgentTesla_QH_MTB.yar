
rule Trojan_BAT_AgentTesla_QH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.QH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 08 07 08 07 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 06 08 91 61 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}