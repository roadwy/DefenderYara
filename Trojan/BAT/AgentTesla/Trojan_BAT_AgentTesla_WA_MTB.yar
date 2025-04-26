
rule Trojan_BAT_AgentTesla_WA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.WA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {06 11 0f 18 64 e0 07 11 0e 11 0f 19 58 58 e0 91 1f 18 62 07 11 0e 11 0f 18 58 58 e0 91 1f 10 62 60 07 11 0e 11 0f 17 58 58 e0 91 1e 62 60 07 11 0e 11 0f 58 e0 91 60 9e 11 0f 1a 58 13 0f 11 0f 1f 3d 44 b9 ff ff ff } //10
		$a_80_1 = {52 65 6c 6f 61 64 2e 63 6f 6d 2e 49 6e 73 70 65 63 74 6f 72 4d 75 2e 57 65 62 } //Reload.com.InspectorMu.Web  3
		$a_80_2 = {48 6f 73 74 45 6e 74 72 79 } //HostEntry  3
		$a_80_3 = {47 65 74 46 72 6f 6d 4c 69 6e 65 } //GetFromLine  3
		$a_80_4 = {57 72 69 74 65 50 72 69 76 61 74 65 50 72 6f 66 69 6c 65 53 74 72 69 6e 67 } //WritePrivateProfileString  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}