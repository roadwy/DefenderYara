
rule Trojan_BAT_AgentTesla_ETN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ETN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {34 00 31 00 47 00 38 00 56 00 48 00 44 00 48 00 48 00 38 00 34 00 43 00 43 00 43 00 35 00 35 00 34 00 44 00 46 00 42 00 35 00 35 00 } //1 41G8VHDHH84CCC554DFB55
		$a_03_1 = {5d 91 0a 06 7e 90 01 03 04 03 1f 16 5d 28 90 01 03 06 61 0b 08 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}