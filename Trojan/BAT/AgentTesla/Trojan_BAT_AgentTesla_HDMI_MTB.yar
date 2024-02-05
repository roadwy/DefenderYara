
rule Trojan_BAT_AgentTesla_HDMI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HDMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0e 0b b7 c7 cb 1e af 8f fc fb 19 4c d9 7f e0 05 f4 13 ef c4 50 a9 18 39 e9 4f fe b6 c7 fb 1e a3 bf ff ca bf 07 66 dc f0 9c 7e ec f7 1d 2f 10 6b a7 8e 27 7f 9d fe 0c b6 bd c4 fa 99 7f 0f 4c fd } //01 00 
		$a_01_1 = {7e d3 f1 fc 51 10 ef 77 7c 9d b0 fd ad b6 7c f1 96 fe } //00 00 
	condition:
		any of ($a_*)
 
}