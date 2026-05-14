
rule HackTool_MacOS_Metasploit_P1{
	meta:
		description = "HackTool:MacOS/Metasploit.P1,SIGNATURE_TYPE_MACHOHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_00_0 = {40 00 80 d2 21 00 80 d2 02 00 80 d2 10 40 a0 d2 30 0c 80 f2 01 00 00 d4 ed 03 00 aa } //2
		$a_00_1 = {e1 03 00 91 21 00 02 8b 02 02 80 d2 10 40 a0 d2 10 0d 80 f2 01 00 00 d4 } //2
		$a_00_2 = {e0 03 0d aa 01 00 80 d2 10 40 a0 d2 50 0d 80 f2 01 00 00 d4 e0 03 0d aa 01 00 80 d2 02 00 80 d2 10 40 a0 d2 d0 03 80 f2 01 00 00 d4 } //2
		$a_00_3 = {10 40 a0 d2 50 0b 80 f2 } //2
		$a_00_4 = {10 40 a0 d2 70 07 80 f2 } //2
		$a_01_5 = {5f 6d 6d 61 70 00 5f 6d 70 72 6f 74 65 63 74 00 } //1 浟慭p浟牰瑯捥t
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_01_5  & 1)*1) >=11
 
}