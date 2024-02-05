
rule Trojan_BAT_Agent_MRS_MTB{
	meta:
		description = "Trojan:BAT/Agent.MRS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {09 11 04 9a 0b 06 07 6f 90 01 04 6f 90 01 04 11 04 17 13 06 20 90 01 04 20 90 01 04 20 90 01 04 61 20 90 01 04 40 90 01 04 20 90 01 04 13 06 20 90 01 04 58 00 58 13 04 11 04 09 8e 69 32 b8 02 03 06 6f 90 01 04 6f 90 01 04 0c 08 14 04 6f 90 01 04 2a 90 00 } //01 00 
		$a_02_1 = {2d 11 14 fe 90 01 0f 7e 90 01 0e 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}