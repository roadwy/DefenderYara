
rule Trojan_BAT_AgentTesla_PF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 32 35 35 65 64 64 66 2d 62 63 30 30 2d 34 65 35 31 2d 62 65 61 38 2d 66 32 66 33 33 32 35 38 62 34 34 39 } //01 00  d255eddf-bc00-4e51-bea8-f2f33258b449
		$a_01_1 = {43 72 65 61 74 65 55 72 6c 43 61 63 68 65 45 6e 74 72 79 57 } //01 00  CreateUrlCacheEntryW
		$a_01_2 = {43 6f 6d 6d 69 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 57 } //01 00  CommitUrlCacheEntryW
		$a_01_3 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //01 00  get_ExecutablePath
		$a_01_4 = {67 65 74 5f 6e 65 74 5f 68 74 74 70 5f 63 6f 6e 74 65 6e 74 5f 62 75 66 66 65 72 73 69 7a 65 5f 65 78 63 65 65 64 65 64 } //01 00  get_net_http_content_buffersize_exceeded
		$a_01_5 = {67 65 74 5f 6e 65 74 5f 68 74 74 70 5f 63 6c 69 65 6e 74 5f 73 65 6e 64 5f 63 6f 6d 70 6c 65 74 65 64 } //01 00  get_net_http_client_send_completed
		$a_01_6 = {67 65 74 5f 6e 65 74 5f 68 74 74 70 5f 6f 70 65 72 61 74 69 6f 6e 5f 73 74 61 72 74 65 64 } //00 00  get_net_http_operation_started
	condition:
		any of ($a_*)
 
}