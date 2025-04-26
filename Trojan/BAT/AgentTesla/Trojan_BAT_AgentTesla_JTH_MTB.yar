
rule Trojan_BAT_AgentTesla_JTH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 67 68 67 68 67 68 66 68 66 68 66 68 2e 30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d 2f 52 75 6e 50 45 2e 64 6c 6c } //2 https://ghghghfhfhfh.000webhostapp.com/RunPE.dll
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_3 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}