
rule HackTool_Win64_Rsoctun_GA_MTB{
	meta:
		description = "HackTool:Win64/Rsoctun.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 34 90 67 48 ff c2 48 39 d3 7f f4 } //3
		$a_01_1 = {2f 72 6f 6f 74 2f 6b 6c 70 6f 5f 72 65 76 65 72 73 65 5f 73 6f 63 6b 73 2d 6e 65 77 5f 6c 6f 67 67 65 72 5f 73 65 74 74 69 6e 67 73 2f 63 6d 64 2f 72 65 76 65 72 73 65 5f 73 6f 63 6b 73 } //2 /root/klpo_reverse_socks-new_logger_settings/cmd/reverse_socks
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}