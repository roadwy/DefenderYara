
rule Backdoor_Linux_Gafgyt_AX_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.AX!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 54 44 50 50 53 } //1 STDPPS
		$a_01_1 = {53 59 4e 41 43 4b } //1 SYNACK
		$a_01_2 = {4c 4f 4c 4e 4f 47 54 46 4f } //1 LOLNOGTFO
		$a_01_3 = {48 54 54 50 48 45 58 } //1 HTTPHEX
		$a_00_4 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
		$a_00_5 = {54 53 6f 75 72 63 65 20 45 6e 67 69 6e 65 20 51 75 65 72 79 20 2b 20 2f 78 35 34 2f 78 35 33 2f 78 36 66 2f 78 37 35 2f 78 37 32 2f 78 36 33 2f 78 36 35 2f 78 32 30 2f 78 34 35 2f 78 36 65 2f 78 36 37 2f 78 36 39 2f 78 36 65 2f 78 36 35 2f 78 32 30 2f 78 35 31 2f 78 37 35 2f 78 36 35 2f 78 37 32 2f 78 37 39 } //1 TSource Engine Query + /x54/x53/x6f/x75/x72/x63/x65/x20/x45/x6e/x67/x69/x6e/x65/x20/x51/x75/x65/x72/x79
		$a_01_6 = {74 65 6c 6e 65 74 61 64 6d 69 6e } //1 telnetadmin
		$a_00_7 = {37 75 6a 4d 6b 6f 30 61 64 6d 69 6e } //1 7ujMko0admin
		$a_01_8 = {54 43 50 53 4c 41 4d } //1 TCPSLAM
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1) >=4
 
}