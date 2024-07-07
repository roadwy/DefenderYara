
rule Trojan_BAT_AgentTesla_SPP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 07 8e 69 5d 07 11 05 07 8e 69 5d 91 08 11 05 1f 16 5d 6f 90 01 03 0a 61 28 90 01 03 0a 07 11 05 17 58 07 8e 69 5d 91 28 90 01 03 0a 59 20 90 01 03 00 58 20 90 01 03 00 5d d2 9c 00 11 05 15 58 13 05 11 05 16 fe 04 16 fe 01 13 06 11 06 2d ac 90 00 } //4
		$a_01_1 = {48 00 6f 00 74 00 65 00 6c 00 53 00 69 00 6d 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 HotelSim.Properties.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}