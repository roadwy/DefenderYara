
rule HackTool_Win32_Chisel_A{
	meta:
		description = "HackTool:Win32/Chisel.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {63 68 69 73 65 6c 2d 76 ?? 2d 63 6c 69 65 6e 74 } //2
		$a_01_1 = {63 68 69 73 65 6c 63 6c 69 65 6e 74 63 6c 6f 73 65 64 } //1 chiselclientclosed
		$a_01_2 = {63 68 69 73 65 6c 2d 63 68 75 6e 6b 65 64 63 6f 6d 6d 61 6e 64 } //1 chisel-chunkedcommand
		$a_01_3 = {73 65 6e 64 63 68 69 73 65 6c } //1 sendchisel
		$a_01_4 = {43 48 49 53 45 4c 5f 4b 45 59 } //1 CHISEL_KEY
		$a_01_5 = {63 68 69 73 65 6c 2e 70 69 64 } //1 chisel.pid
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}