
rule Trojan_BAT_AgentTesla_SG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 06 17 58 07 8e 69 5d 91 13 06 09 06 09 8e 69 5d 91 13 07 07 06 07 06 91 11 07 61 11 06 59 20 00 01 00 00 58 d2 9c 06 17 58 0a 06 07 8e 69 fe 04 13 08 11 08 2d c9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_SG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 20 00 01 00 00 13 0c 11 0b 17 58 13 0d 11 0b 20 ?? ?? ?? 00 5d 13 0e 11 0d 20 ?? ?? ?? 00 5d 13 0f 11 06 11 0f 91 11 0c 58 13 10 11 06 11 0e 91 13 11 11 07 11 0b 1f 16 5d 91 13 12 11 11 11 12 61 13 13 11 06 11 0e 11 13 11 10 59 11 0c 5d d2 9c 00 11 0b 17 58 13 0b 11 0b 20 ?? ?? ?? 00 fe 04 13 14 11 14 2d 98 } //2
		$a_01_1 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}