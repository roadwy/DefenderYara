
rule Trojan_BAT_RaspberryRobin_MBEY_MTB{
	meta:
		description = "Trojan:BAT/RaspberryRobin.MBEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 54 13 00 00 95 5f 11 1c 20 af 04 00 00 95 61 59 80 44 00 00 04 38 63 01 00 00 7e 44 00 00 04 11 1c 20 9c 0f 00 00 } //01 00 
		$a_01_1 = {20 b6 0b 00 00 95 5f 7e 37 00 00 04 20 19 0f 00 00 95 61 59 13 3b 38 b8 00 00 00 11 3b 7e 37 00 00 04 20 bb 02 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}