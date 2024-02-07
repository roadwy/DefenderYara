
rule Trojan_BAT_AgentTesla_NEH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 66 36 37 36 63 37 36 2d 38 30 65 31 2d 34 32 33 39 2d 39 35 62 62 2d 38 33 64 30 66 36 64 30 64 61 37 38 } //01 00  1f676c76-80e1-4239-95bb-83d0f6d0da78
		$a_01_1 = {66 68 64 64 73 64 73 68 66 64 64 66 68 68 73 } //01 00  fhddsdshfddfhhs
		$a_01_2 = {73 64 67 66 73 73 66 68 73 61 68 66 64 70 } //01 00  sdgfssfhsahfdp
		$a_01_3 = {67 6a 6a 6a 6a 6a 73 66 6a 64 6a 6a 6a 64 } //01 00  gjjjjjsfjdjjjd
		$a_01_4 = {4a 52 2e 49 6e 6e 6f 2e 53 65 74 75 70 } //01 00  JR.Inno.Setup
		$a_01_5 = {4f 62 66 75 73 63 61 74 65 64 42 79 47 6f 6c 69 61 74 68 } //00 00  ObfuscatedByGoliath
	condition:
		any of ($a_*)
 
}