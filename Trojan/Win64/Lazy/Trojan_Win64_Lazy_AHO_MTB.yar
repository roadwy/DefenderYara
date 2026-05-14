
rule Trojan_Win64_Lazy_AHO_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 65 63 72 79 70 74 53 6f 63 6b 65 74 4b 65 79 50 61 79 6c 6f 61 64 4d 61 6e 61 67 65 } //10 DecryptSocketKeyPayloadManage
		$a_01_1 = {44 69 73 63 61 72 64 5f 50 61 79 6c 6f 61 64 5f 44 65 74 61 69 6c } //20 Discard_Payload_Detail
		$a_01_2 = {55 6e 69 6e 73 74 61 6c 6c 5f 50 61 79 6c 6f 61 64 } //30 Uninstall_Payload
		$a_01_3 = {42 61 74 63 68 5f 50 61 79 6c 6f 61 64 5f 54 6f 6b 65 6e 5f 54 61 67 5f 53 79 6e 63 } //40 Batch_Payload_Token_Tag_Sync
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30+(#a_01_3  & 1)*40) >=100
 
}