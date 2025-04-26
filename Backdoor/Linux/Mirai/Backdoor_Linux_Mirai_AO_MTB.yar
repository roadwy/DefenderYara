
rule Backdoor_Linux_Mirai_AO_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AO!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 75 72 65 6e 65 74 77 6f 72 6b 73 2e 63 6f 6d 2f 48 4e 41 50 31 2f 60 63 64 20 2f 74 6d 70 20 26 26 20 72 6d 20 2d 72 66 } //1 purenetworks.com/HNAP1/`cd /tmp && rm -rf
		$a_00_1 = {63 6e 63 2e 6e 6f 74 61 62 6f 74 6e 65 74 2e 74 6b 2f 6e 6f 74 61 62 6f 74 6e 65 74 2f 6e 6f 74 61 62 6f 74 6e 65 74 } //2 cnc.notabotnet.tk/notabotnet/notabotnet
		$a_02_2 = {63 64 20 2f 76 61 72 3b 20 72 6d 20 2d 72 66 20 6e 69 67 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-03] 2e [0-03] 2e [0-03] 2e [0-03] 2f 48 69 6c 69 78 2e 73 68 20 2d 4f 20 68 78 3b 20 63 68 6d 6f 64 20 37 37 37 20 68 78 3b 20 2e 2f 68 78 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*2+(#a_02_2  & 1)*2) >=3
 
}