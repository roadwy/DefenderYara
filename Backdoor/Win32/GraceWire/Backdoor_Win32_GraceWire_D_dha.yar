
rule Backdoor_Win32_GraceWire_D_dha{
	meta:
		description = "Backdoor:Win32/GraceWire.D!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 09 00 00 "
		
	strings :
		$a_01_0 = {5b 63 6f 6e 66 69 67 2e 63 3a 43 6f 6e 66 69 67 46 69 6c 6c 53 65 72 76 65 72 73 } //1 [config.c:ConfigFillServers
		$a_01_1 = {5b 72 64 70 2e 63 3a 52 64 70 43 68 61 6e 6e 65 6c 41 64 64 3a } //1 [rdp.c:RdpChannelAdd:
		$a_01_2 = {5b 74 61 72 67 65 74 2e 63 3a 57 69 6e 4d 61 69 6e 3a } //3 [target.c:WinMain:
		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 53 00 41 00 53 00 47 00 65 00 6e 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //1 SoftwareSASGeneration
		$a_01_4 = {63 00 6d 00 64 00 20 00 2f 00 43 00 20 00 6e 00 65 00 74 00 20 00 6c 00 6f 00 63 00 61 00 6c 00 67 00 72 00 6f 00 75 00 70 00 } //1 cmd /C net localgroup
		$a_01_5 = {64 65 73 74 72 6f 79 5f 6f 73 } //1 destroy_os
		$a_01_6 = {74 61 72 67 65 74 5f 75 70 6c 6f 61 64 } //1 target_upload
		$a_01_7 = {74 61 72 67 65 74 5f 72 64 70 } //1 target_rdp
		$a_01_8 = {74 61 72 67 65 74 5f 6d 6f 64 75 6c 65 5f 6c 6f 61 64 5f 65 78 74 65 72 6e 61 6c } //1 target_module_load_external
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=4
 
}