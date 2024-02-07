
rule Trojan_BAT_AgentTesla_NYR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 ab 02 00 70 a2 25 17 02 7b 26 00 00 04 a2 25 18 72 bd 02 00 70 a2 25 19 02 7b 28 00 00 04 a2 25 1a 72 cd 02 00 70 a2 } //01 00 
		$a_81_1 = {73 74 6d 74 64 61 74 65 7e 5e 70 61 74 49 6e 73 43 6f 7e 5e 69 6e 73 4c } //01 00  stmtdate~^patInsCo~^insL
		$a_81_2 = {48 4c 53 5f 53 65 72 76 69 63 65 2e 50 72 6f 6a 65 63 74 49 6e 73 74 61 6c 6c 65 72 2e 72 65 73 } //01 00  HLS_Service.ProjectInstaller.res
		$a_01_3 = {66 35 36 38 65 31 37 30 2d 39 61 35 36 2d 34 35 61 64 2d 61 37 30 32 2d 35 33 61 66 32 65 37 39 36 66 36 64 } //00 00  f568e170-9a56-45ad-a702-53af2e796f6d
	condition:
		any of ($a_*)
 
}