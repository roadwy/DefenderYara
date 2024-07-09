
rule Trojan_BAT_AgentTesla_ABUF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 20 00 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 07 08 11 07 6f ?? 00 00 0a 00 09 18 58 0d 00 09 07 6f ?? 00 00 0a fe 04 13 08 11 08 2d d1 } //4
		$a_01_1 = {51 00 55 00 41 00 4e 00 4c 00 59 00 42 00 41 00 4e 00 48 00 41 00 4e 00 47 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 QUANLYBANHANG.Properties.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}