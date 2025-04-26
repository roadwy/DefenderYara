
rule HackTool_MacOS_Rubilyn_B_MTB{
	meta:
		description = "HackTool:MacOS/Rubilyn.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {64 65 62 75 67 2e 72 75 62 69 6c 79 6e 2e } //1 debug.rubilyn.
		$a_00_1 = {65 6e 74 65 72 20 69 63 6d 70 20 70 61 74 68 20 66 6f 72 20 62 61 63 6b 64 6f 6f 72 3a } //1 enter icmp path for backdoor:
		$a_01_2 = {48 41 52 44 43 4f 52 45 20 45 53 54 2e 20 31 39 38 33 } //1 HARDCORE EST. 1983
		$a_00_3 = {65 6e 74 65 72 20 70 72 6f 63 65 73 73 20 69 64 20 74 6f 20 67 69 76 65 20 72 6f 6f 74 3a } //1 enter process id to give root:
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}