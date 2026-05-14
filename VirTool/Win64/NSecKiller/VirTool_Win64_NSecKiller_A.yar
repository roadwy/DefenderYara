
rule VirTool_Win64_NSecKiller_A{
	meta:
		description = "VirTool:Win64/NSecKiller.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 53 65 63 4b 72 6e 6c 2e 73 79 73 } //1 NSecKrnl.sys
		$a_01_1 = {42 6c 61 63 6b 53 6e 75 66 6b 69 6e } //1 BlackSnufkin
		$a_01_2 = {42 59 4f 56 44 20 50 72 6f 63 65 73 73 20 4b 69 6c 6c 65 72 } //1 BYOVD Process Killer
		$a_01_3 = {4b 69 6c 6c 73 20 61 20 70 72 6f 63 65 73 73 20 62 79 20 6e 61 6d 65 } //1 Kills a process by name
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}