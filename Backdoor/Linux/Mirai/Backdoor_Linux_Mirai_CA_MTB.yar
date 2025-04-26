
rule Backdoor_Linux_Mirai_CA_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {f0 40 2d e9 48 70 9f e5 00 20 97 e5 03 00 52 e3 40 60 9f e5 01 50 82 e2 21 4c a0 e1 21 c4 a0 e1 21 e8 a0 e1 ff 00 00 e2 f0 80 bd 08 05 30 a0 e3 93 02 02 e0 06 30 82 e0 06 00 c2 e7 00 50 87 e5 04 40 c3 e5 02 c0 c3 e5 03 e0 c3 e5 01 10 c3 e5 f0 80 bd e8 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
rule Backdoor_Linux_Mirai_CA_MTB_2{
	meta:
		description = "Backdoor:Linux/Mirai.CA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 4d 49 52 41 49 } //10 /bin/busybox MIRAI
		$a_00_1 = {76 73 74 61 72 63 61 6d 32 30 31 35 } //1 vstarcam2015
		$a_00_2 = {74 65 6c 65 63 6f 6d 61 64 6d 69 6e } //1 telecomadmin
		$a_00_3 = {74 6f 6f 72 } //1 toor
		$a_00_4 = {75 64 70 70 6c 61 69 6e } //1 udpplain
		$a_00_5 = {74 63 70 72 61 77 } //1 tcpraw
		$a_00_6 = {61 64 6d 31 32 33 34 69 6e 74 65 6c 65 63 6f 6d } //1 adm1234intelecom
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=13
 
}