
rule HackTool_MacOS_Netspy_A_MTB{
	meta:
		description = "HackTool:MacOS/Netspy.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {6e 65 74 73 70 79 2f 63 6f 72 65 2f 73 70 79 2e 53 70 79 } //1 netspy/core/spy.Spy
		$a_00_1 = {6e 65 74 73 70 79 2f 63 6f 72 65 2f 73 70 79 2e 67 6f 53 70 79 } //1 netspy/core/spy.goSpy
		$a_00_2 = {6e 65 74 73 70 79 2f 63 6f 72 65 2f 61 72 70 2e 63 68 65 63 6b 4f 73 } //1 netspy/core/arp.checkOs
		$a_00_3 = {2f 6e 65 74 73 70 79 2f 63 6d 64 2f 6e 65 74 73 70 79 2f 6d 61 69 6e 2e 67 6f } //1 /netspy/cmd/netspy/main.go
		$a_00_4 = {6e 65 74 73 70 79 2f 63 6f 72 65 2f 70 69 6e 67 2e 53 70 79 } //1 netspy/core/ping.Spy
		$a_00_5 = {6e 65 74 73 70 79 2f 63 6f 72 65 2f 73 70 79 2e 67 65 6e 41 6c 6c 43 49 44 52 } //1 netspy/core/spy.genAllCIDR
		$a_00_6 = {67 6f 5f 70 61 63 6b 61 67 65 2f 6e 65 74 73 70 79 2f 63 6f 72 65 2f 73 70 79 2f 73 70 79 2e 67 6f } //1 go_package/netspy/core/spy/spy.go
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}