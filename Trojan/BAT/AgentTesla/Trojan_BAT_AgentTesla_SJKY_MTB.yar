
rule Trojan_BAT_AgentTesla_SJKY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SJKY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_02_0 = {11 06 11 05 11 (0f|1f) 9a 1f 10 28 [0-04] 6f [0-04] 00 11 (0f|1f) 17 d6 13 (0f|1f) 11 (0f|1f) 11 [0-02] 31 e0 } //1
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //1 GetObjectValue
		$a_81_3 = {4c 61 74 65 47 65 74 } //1 LateGet
		$a_81_4 = {43 61 6c 6c 42 79 4e 61 6d 65 } //1 CallByName
		$a_81_5 = {51 75 61 6e 4c 79 42 61 6e 47 69 61 79 2e 43 43 4d } //1 QuanLyBanGiay.CCM
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}