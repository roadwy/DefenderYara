
rule Trojan_BAT_AgentTesla_SJKY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SJKY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {11 06 11 05 11 90 03 01 01 0f 1f 9a 1f 10 28 90 02 04 6f 90 02 04 00 11 90 03 01 01 0f 1f 17 d6 13 90 03 01 01 0f 1f 11 90 03 01 01 0f 1f 11 90 02 02 31 e0 90 00 } //01 00 
		$a_81_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_2 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //01 00  GetObjectValue
		$a_81_3 = {4c 61 74 65 47 65 74 } //01 00  LateGet
		$a_81_4 = {43 61 6c 6c 42 79 4e 61 6d 65 } //01 00  CallByName
		$a_81_5 = {51 75 61 6e 4c 79 42 61 6e 47 69 61 79 2e 43 43 4d } //00 00  QuanLyBanGiay.CCM
	condition:
		any of ($a_*)
 
}