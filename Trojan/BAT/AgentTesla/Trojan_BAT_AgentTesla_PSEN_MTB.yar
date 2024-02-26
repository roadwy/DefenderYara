
rule Trojan_BAT_AgentTesla_PSEN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 b0 00 00 0a 0d 16 13 04 2b 32 09 08 17 8d 17 00 00 01 25 16 11 04 8c 63 00 00 01 a2 14 28 aa 90 01 03 28 ae 90 01 03 1f 10 28 b1 90 01 03 86 6f b2 90 01 03 00 11 04 90 00 } //01 00 
		$a_01_1 = {47 65 74 48 61 73 68 43 6f 64 65 } //00 00  GetHashCode
	condition:
		any of ($a_*)
 
}