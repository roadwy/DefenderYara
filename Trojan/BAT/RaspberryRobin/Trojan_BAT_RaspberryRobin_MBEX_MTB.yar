
rule Trojan_BAT_RaspberryRobin_MBEX_MTB{
	meta:
		description = "Trojan:BAT/RaspberryRobin.MBEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 69 02 00 00 95 2e 03 16 2b 01 17 17 59 7e 90 01 01 00 00 04 16 9a 20 71 01 00 00 95 5f 7e 4c 00 00 04 16 9a 20 b5 02 00 00 95 61 58 80 16 00 00 04 90 00 } //01 00 
		$a_81_1 = {74 72 61 63 74 50 4d 41 4f 52 49 } //00 00  tractPMAORI
	condition:
		any of ($a_*)
 
}