
rule Trojan_BAT_AgentTesla_NYI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 09 16 20 00 10 00 00 6f ?? ?? ?? 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 0e 00 11 04 09 16 11 05 6f ?? ?? ?? 0a 00 00 00 11 05 16 fe 02 13 07 11 07 2d cb } //1
		$a_01_1 = {24 65 39 38 65 34 39 62 63 2d 66 32 31 33 2d 34 31 33 62 2d 62 63 39 30 2d 64 63 35 35 63 64 63 65 34 36 63 33 } //1 $e98e49bc-f213-413b-bc90-dc55cdce46c3
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}