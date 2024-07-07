
rule Trojan_BAT_AgentTesla_JOH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JOH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {61 73 73 73 73 73 73 73 73 73 64 64 64 64 64 2e 64 6c 6c } //1 asssssssssddddd.dll
		$a_81_1 = {23 66 2e 64 6c 6c 23 } //1 #f.dll#
		$a_81_2 = {23 66 73 64 66 2e 64 6c 6c 23 } //1 #fsdf.dll#
		$a_81_3 = {23 66 73 64 66 73 64 66 2e 64 6c 6c 23 } //1 #fsdfsdf.dll#
		$a_81_4 = {23 72 2e 64 6c 6c 23 } //1 #r.dll#
		$a_81_5 = {23 73 2e 64 6c 6c 23 } //1 #s.dll#
		$a_81_6 = {67 64 66 67 66 64 67 } //1 gdfgfdg
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}