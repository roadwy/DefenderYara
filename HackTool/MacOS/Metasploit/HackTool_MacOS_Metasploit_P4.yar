
rule HackTool_MacOS_Metasploit_P4{
	meta:
		description = "HackTool:MacOS/Metasploit.P4,SIGNATURE_TYPE_MACHOHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_00_0 = {40 00 80 d2 21 00 80 d2 02 00 80 d2 10 40 a0 d2 30 0c 80 f2 01 00 00 d4 ed 03 00 aa } //2
		$a_00_1 = {e1 8f 1f f8 e1 03 00 91 21 00 02 8b 02 02 80 d2 10 40 a0 d2 50 0c 80 f2 01 00 00 d4 } //2
		$a_00_2 = {10 40 a0 d2 50 0b 80 f2 e0 03 0d aa 01 00 80 d2 01 00 00 d4 e0 03 0d aa 21 00 80 d2 01 00 00 d4 } //2
		$a_00_3 = {e1 03 09 aa 21 20 00 d1 21 85 00 f8 3f 85 00 f8 e1 03 09 aa 21 40 00 d1 e2 03 1f aa 01 00 00 d4 } //2
		$a_01_4 = {5f 6d 6d 61 70 00 5f 6d 70 72 6f 74 65 63 74 00 } //2 浟慭p浟牰瑯捥t
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}