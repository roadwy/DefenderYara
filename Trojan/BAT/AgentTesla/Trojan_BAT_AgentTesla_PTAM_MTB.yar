
rule Trojan_BAT_AgentTesla_PTAM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 37 e1 ff ff 28 90 01 01 00 00 06 fe 0c 01 00 28 90 01 01 00 00 06 20 cf f2 45 fc 20 c9 e6 1e 1d 58 20 5f 6e bf 1e 61 65 20 d7 b7 db 07 58 20 04 00 00 00 63 8d 25 00 00 01 25 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}