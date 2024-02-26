
rule Trojan_BAT_AgentTesla_ASER_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 09 07 8e 69 5d 91 08 09 08 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 07 09 17 58 07 8e 69 5d 91 59 20 00 01 00 00 58 13 07 07 09 07 8e 69 5d 11 07 20 00 01 00 00 5d d2 9c 09 15 58 0d 00 09 16 fe 04 16 fe 01 13 08 11 08 2d 90 00 } //01 00 
		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 4b 00 68 00 6f 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  QuanLyKho.Properties.Resources
	condition:
		any of ($a_*)
 
}