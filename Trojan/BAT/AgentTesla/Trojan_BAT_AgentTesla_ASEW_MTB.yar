
rule Trojan_BAT_AgentTesla_ASEW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5d 91 13 0d 11 0b 11 0c 61 11 0d 59 20 00 01 00 00 58 13 0e 07 11 06 11 0e 20 00 01 00 00 5d d2 9c 06 17 59 0a 06 16 fe 04 16 fe 01 13 0f 11 0f 2d } //1
		$a_01_1 = {54 68 75 63 54 61 70 4e 68 6f 6d 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 ThucTapNhom1.Properties.Resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}