
rule Trojan_BAT_AgentTesla_SG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 20 00 01 00 00 13 0c 11 0b 17 58 13 0d 11 0b 20 90 01 03 00 5d 13 0e 11 0d 20 90 01 03 00 5d 13 0f 11 06 11 0f 91 11 0c 58 13 10 11 06 11 0e 91 13 11 11 07 11 0b 1f 16 5d 91 13 12 11 11 11 12 61 13 13 11 06 11 0e 11 13 11 10 59 11 0c 5d d2 9c 00 11 0b 17 58 13 0b 11 0b 20 90 01 03 00 fe 04 13 14 11 14 2d 98 90 00 } //01 00 
		$a_01_1 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //00 00  set_UseShellExecute
	condition:
		any of ($a_*)
 
}