
rule Trojan_BAT_AgentTesla_AXK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {57 69 6e 46 6f 72 4d 6f 6e 6f 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 WinForMono.Properties.Resources
		$a_81_1 = {53 61 63 68 79 5f 4f 62 72 61 7a 6b 79 } //2 Sachy_Obrazky
		$a_81_2 = {24 61 64 63 37 31 31 61 38 2d 64 36 31 65 2d 34 33 36 61 2d 62 31 63 39 2d 32 61 61 64 64 38 34 38 61 64 37 34 } //2 $adc711a8-d61e-436a-b1c9-2aadd848ad74
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}