
rule Trojan_BAT_AgentTesla_JOH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JOH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {61 73 73 73 73 73 73 73 73 73 64 64 64 64 64 2e 64 6c 6c } //01 00  asssssssssddddd.dll
		$a_81_1 = {23 66 2e 64 6c 6c 23 } //01 00  #f.dll#
		$a_81_2 = {23 66 73 64 66 2e 64 6c 6c 23 } //01 00  #fsdf.dll#
		$a_81_3 = {23 66 73 64 66 73 64 66 2e 64 6c 6c 23 } //01 00  #fsdfsdf.dll#
		$a_81_4 = {23 72 2e 64 6c 6c 23 } //01 00  #r.dll#
		$a_81_5 = {23 73 2e 64 6c 6c 23 } //01 00  #s.dll#
		$a_81_6 = {67 64 66 67 66 64 67 } //00 00  gdfgfdg
	condition:
		any of ($a_*)
 
}