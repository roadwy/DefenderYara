
rule Trojan_Linux_IPStorm_A_MTB{
	meta:
		description = "Trojan:Linux/IPStorm.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 74 6f 72 6d 2f 70 6f 77 65 72 73 68 65 6c 6c 2e 28 2a 42 61 63 6b 65 6e 64 29 2e 53 74 61 72 74 50 72 6f 63 65 73 73 } //1 storm/powershell.(*Backend).StartProcess
		$a_00_1 = {73 74 6f 72 6d 2f 62 61 63 6b 73 68 65 6c 6c 2e 53 74 61 72 74 53 65 72 76 65 72 } //1 storm/backshell.StartServer
		$a_00_2 = {73 74 6f 72 6d 2f 72 65 71 75 65 5f 63 6c 69 65 6e 74 2f 77 6f 72 6b 65 72 73 2f 62 72 75 74 65 73 73 68 } //1 storm/reque_client/workers/brutessh
		$a_00_3 = {61 76 62 79 70 61 73 73 } //1 avbypass
		$a_00_4 = {73 74 6f 72 6d 2f 64 64 62 } //1 storm/ddb
		$a_00_5 = {73 74 6f 72 6d 2f 6d 61 6c 77 61 72 65 2d 67 75 61 72 64 2f 6d 61 6c 77 61 72 65 2d 67 75 61 72 64 2e 67 6f } //1 storm/malware-guard/malware-guard.go
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}