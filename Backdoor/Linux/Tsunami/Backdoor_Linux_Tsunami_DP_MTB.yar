
rule Backdoor_Linux_Tsunami_DP_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.DP!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 08 0f b6 00 0f be c0 89 04 24 e8 90 01 04 89 c3 8b 45 0c 0f b6 00 0f be c0 89 04 24 e8 90 01 04 39 c3 75 90 01 01 8b 45 0c 40 8b 55 08 42 89 44 24 04 89 14 24 e8 90 01 04 85 c0 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}