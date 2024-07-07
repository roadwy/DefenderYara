
rule HackTool_Linux_ThcHydra_A{
	meta:
		description = "HackTool:Linux/ThcHydra.A,SIGNATURE_TYPE_ELFHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 45 4c 4f 20 68 79 64 72 61 } //2 HELO hydra
		$a_01_1 = {45 48 4c 4f 20 68 79 64 72 61 } //2 EHLO hydra
		$a_01_2 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 48 79 64 72 61 20 50 72 6f 78 79 29 } //2 Mozilla/5.0 (Hydra Proxy)
		$a_00_3 = {2e 2f 68 79 64 72 61 2e 72 65 73 74 6f 72 65 20 77 61 73 20 77 72 69 74 74 65 6e } //2 ./hydra.restore was written
		$a_00_4 = {68 79 64 72 61 20 2d 4c 20 75 73 65 72 6c 69 73 74 2e 74 78 74 } //2 hydra -L userlist.txt
		$a_01_5 = {5b 53 54 41 54 55 53 5d 20 61 74 74 61 63 6b 20 66 69 6e 69 73 68 65 64 20 66 6f 72 20 25 73 } //2 [STATUS] attack finished for %s
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}