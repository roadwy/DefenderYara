
rule Trojan_BAT_Tasker_MBDT_MTB{
	meta:
		description = "Trojan:BAT/Tasker.MBDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 73 01 00 70 20 00 01 00 00 14 14 17 8d 90 01 01 00 00 01 25 16 09 6f 90 01 01 00 00 0a a2 28 90 01 01 00 00 0a 74 90 01 01 00 00 01 13 04 11 04 6f 90 01 01 00 00 0a 16 9a 7e 90 01 01 00 00 04 13 0a 11 0a 28 90 00 } //01 00 
		$a_01_1 = {42 75 73 69 6e 65 73 73 53 69 6d 75 6c 61 74 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  BusinessSimulation.Properties.Resources
	condition:
		any of ($a_*)
 
}