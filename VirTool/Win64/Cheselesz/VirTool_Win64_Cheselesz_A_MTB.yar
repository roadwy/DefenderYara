
rule VirTool_Win64_Cheselesz_A_MTB{
	meta:
		description = "VirTool:Win64/Cheselesz.A!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {2f 65 78 65 63 2f 65 78 65 63 5f 77 69 6e 64 6f 77 73 2e 67 6f } //1 /exec/exec_windows.go
		$a_01_1 = {2e 73 65 6e 64 44 4e 53 51 75 65 72 79 } //1 .sendDNSQuery
		$a_01_2 = {2e 73 68 75 74 64 6f 77 6e } //1 .shutdown
		$a_01_3 = {63 6d 64 2f 73 68 65 6c 6c 2f 63 68 61 73 68 65 6c 6c 2e 67 6f } //1 cmd/shell/chashell.go
		$a_01_4 = {29 2e 52 65 6d 6f 74 65 41 64 64 72 } //1 ).RemoteAddr
		$a_01_5 = {2e 73 65 6e 64 49 6e 66 6f 50 61 63 6b 65 74 } //1 .sendInfoPacket
		$a_01_6 = {29 2e 47 65 74 48 6f 73 74 6e 61 6d 65 } //1 ).GetHostname
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}