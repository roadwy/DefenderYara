
rule Trojan_BAT_AgentTesla_JNE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 90 01 03 0a 03 6f 90 01 03 0a 6f 90 01 03 0a 0a 73 90 01 03 0a 0c 08 06 6f 90 01 03 0a 00 08 18 6f 90 01 03 0a 00 08 6f 90 01 03 0a 0d 09 02 16 02 8e 69 6f 90 01 03 0a 13 04 08 6f 90 00 } //01 00 
		$a_01_1 = {39 30 61 63 63 38 65 64 2d 66 31 32 65 2d 34 32 32 32 2d 38 30 32 66 2d 63 32 62 30 35 61 36 35 33 35 63 61 } //01 00 
		$a_01_2 = {4f 70 65 6e 43 43 20 47 55 49 } //00 00 
	condition:
		any of ($a_*)
 
}