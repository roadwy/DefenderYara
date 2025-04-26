
rule HackTool_Linux_BruteForce_A_MTB{
	meta:
		description = "HackTool:Linux/BruteForce.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 73 6a 65 73 75 73 63 61 6e 2f 65 78 70 6c 6f 69 74 2f 73 73 68 73 63 61 6e 2e 42 72 75 74 65 73 73 68 } //1 masjesuscan/exploit/sshscan.Brutessh
		$a_01_1 = {65 78 70 6c 6f 69 74 2f 65 6e 76 73 63 61 6e 2e 47 65 74 57 65 62 61 73 73 68 74 74 70 } //1 exploit/envscan.GetWebasshttp
		$a_01_2 = {2f 72 6f 6f 74 2f 6d 61 73 6a 65 73 75 2f 73 63 61 6e 2f 65 78 70 6c 6f 69 74 2f 74 70 6c 69 6e 6b 2f 6d 61 69 6e 2e 67 6f } //1 /root/masjesu/scan/exploit/tplink/main.go
		$a_01_3 = {6d 61 73 6a 65 73 75 73 63 61 6e 2f 65 78 70 6c 6f 69 74 2f 74 70 6c 69 6e 6b 2e 43 76 65 32 30 32 33 31 33 38 39 } //1 masjesuscan/exploit/tplink.Cve20231389
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}