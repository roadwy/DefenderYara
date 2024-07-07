
rule HackTool_Win32_Chisel_B{
	meta:
		description = "HackTool:Win32/Chisel.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {63 68 69 73 65 6c 2d 76 90 01 01 2d 63 6c 69 65 6e 74 90 00 } //2
		$a_01_1 = {63 68 69 73 65 6c 63 6c 69 65 6e 74 63 6c 6f 73 65 64 } //1 chiselclientclosed
		$a_01_2 = {73 65 6e 64 63 68 69 73 65 6c } //1 sendchisel
		$a_01_3 = {43 48 49 53 45 4c 5f 4b 45 59 } //1 CHISEL_KEY
		$a_01_4 = {69 6e 76 61 6c 69 64 6c 6f 6f 6b 75 70 } //1 invalidlookup
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}