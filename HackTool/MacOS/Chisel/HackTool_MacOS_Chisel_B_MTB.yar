
rule HackTool_MacOS_Chisel_B_MTB{
	meta:
		description = "HackTool:MacOS/Chisel.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 48 49 53 45 4c 5f 43 4f 4e 4e 45 43 54 } //1 CHISEL_CONNECT
		$a_01_1 = {73 65 6e 64 63 68 69 73 65 6c } //1 sendchisel
		$a_01_2 = {63 68 69 73 65 6c 2e 70 69 64 } //1 chisel.pid
		$a_01_3 = {63 68 69 73 65 6c 63 6c 69 65 6e 74 63 6c 6f 73 65 64 } //1 chiselclientclosed
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}