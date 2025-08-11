
rule VirTool_Win64_Luidek_B{
	meta:
		description = "VirTool:Win64/Luidek.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6c 75 70 6f 2f 6c 75 70 6f 2d 63 6c 69 65 6e 74 2f 63 6d 64 2e 52 65 73 70 6f 6e 73 65 } //1 lupo/lupo-client/cmd.Response
		$a_81_1 = {6c 75 70 6f 2f 6c 75 70 6f 2d 63 6c 69 65 6e 74 2f 63 6f 72 65 } //1 lupo/lupo-client/core
		$a_01_2 = {6c 75 70 6f 62 61 63 6b 65 78 65 63 73 68 6f 77 6b 69 6c 6c 6c 6f 61 64 72 } //1 lupobackexecshowkillloadr
		$a_01_3 = {6d 61 74 74 6e 2f 67 6f 2d 73 68 65 6c 6c 77 6f 72 64 73 } //1 mattn/go-shellwords
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}