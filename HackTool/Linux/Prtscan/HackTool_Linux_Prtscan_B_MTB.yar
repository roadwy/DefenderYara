
rule HackTool_Linux_Prtscan_B_MTB{
	meta:
		description = "HackTool:Linux/Prtscan.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {77 77 77 2e 6c 79 73 61 74 6f 72 2e 6c 69 75 2e 73 65 2f 7e 70 65 6e 2f 70 6e 73 63 61 6e [0-10] 43 6f 6d 6d 61 6e 64 20 6c 69 6e 65 } //1
		$a_01_1 = {50 4e 53 63 61 6e 2c 20 76 65 72 73 69 6f 6e 20 25 73 20 2d 20 25 73 20 25 73 } //1 PNScan, version %s - %s %s
		$a_01_2 = {54 43 50 20 70 6f 72 74 20 73 63 61 6e 6e 65 72 } //1 TCP port scanner
		$a_01_3 = {4c 6f 6f 6b 75 70 20 61 6e 64 20 70 72 69 6e 74 20 68 6f 73 74 6e 61 6d 65 73 } //1 Lookup and print hostnames
		$a_01_4 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //1 gethostbyname
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}