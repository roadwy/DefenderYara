
rule Backdoor_Linux_Gafgyt_M_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.M!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 43 50 53 4c 41 4d } //1 TCPSLAM
		$a_01_1 = {4c 4f 4c 4e 4f 47 54 46 4f } //1 LOLNOGTFO
		$a_01_2 = {49 73 24 75 70 65 72 40 64 6d 69 6e } //1 Is$uper@dmin
		$a_01_3 = {78 6d 68 64 69 70 63 } //1 xmhdipc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}