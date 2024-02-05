
rule Trojan_BAT_AgentTesla_AEH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 07 00 00 0a 00 "
		
	strings :
		$a_03_0 = {07 02 08 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a d2 6f 90 01 03 0a 00 00 08 17 58 0c 08 06 fe 04 0d 09 2d d9 90 00 } //0a 00 
		$a_03_1 = {25 16 02 08 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a d2 9c 6f 90 01 03 0a 00 00 08 17 58 0c 08 06 fe 04 0d 09 2d d0 90 00 } //02 00 
		$a_80_2 = {47 65 74 54 79 70 65 73 } //GetTypes  02 00 
		$a_80_3 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //GetExportedTypes  02 00 
		$a_80_4 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  02 00 
		$a_80_5 = {49 6e 76 6f 6b 65 } //Invoke  02 00 
		$a_80_6 = {52 65 70 6c 61 63 65 } //Replace  00 00 
	condition:
		any of ($a_*)
 
}