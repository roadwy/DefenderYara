
rule Trojan_BAT_AgentTesla_NVX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 00 2b 31 16 2b 31 2b 36 2b 3b 00 09 08 6f 90 01 01 00 00 0a 00 00 de 11 90 00 } //1
		$a_01_1 = {15 a2 09 09 0b 00 00 00 10 00 01 00 02 00 00 01 } //1
		$a_01_2 = {24 30 38 38 65 31 35 66 65 2d 61 66 64 62 2d 34 37 31 63 2d 38 61 38 30 2d 37 65 38 34 62 33 39 30 34 30 31 63 } //1 $088e15fe-afdb-471c-8a80-7e84b390401c
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}