
rule Trojan_BAT_AgentTesla_NWB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {1f 61 95 2e 03 17 2b 01 16 7e 19 00 00 04 7e 21 00 00 04 19 9a 20 4f 09 00 00 95 e0 95 7e 21 00 00 04 19 9a 20 9f 08 00 00 95 61 7e 21 00 00 04 19 9a 20 40 10 00 00 95 2e 09 } //01 00 
		$a_01_1 = {57 94 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 01 } //01 00 
		$a_01_2 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //01 00  GetFolderPath
		$a_01_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_01_4 = {41 70 70 44 6f 6d 61 69 6e } //00 00  AppDomain
	condition:
		any of ($a_*)
 
}