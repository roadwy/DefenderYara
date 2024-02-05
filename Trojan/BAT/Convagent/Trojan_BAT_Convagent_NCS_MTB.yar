
rule Trojan_BAT_Convagent_NCS_MTB{
	meta:
		description = "Trojan:BAT/Convagent.NCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {7e 03 00 00 04 14 fe 01 0a 06 2c 22 00 72 90 01 03 70 d0 90 01 03 02 28 90 01 03 0a 6f 90 01 03 0a 73 90 01 03 0a 0b 07 80 90 01 03 04 00 7e 90 01 03 04 0c 2b 00 08 2a 90 00 } //01 00 
		$a_01_1 = {78 76 69 64 2e 46 6f 72 6d 31 } //00 00 
	condition:
		any of ($a_*)
 
}