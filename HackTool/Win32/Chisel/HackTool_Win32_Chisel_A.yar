
rule HackTool_Win32_Chisel_A{
	meta:
		description = "HackTool:Win32/Chisel.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {63 68 69 73 65 6c 2d 76 90 01 01 2d 63 6c 69 65 6e 74 90 00 } //01 00 
		$a_01_1 = {63 68 69 73 65 6c 63 6c 69 65 6e 74 63 6c 6f 73 65 64 } //01 00  chiselclientclosed
		$a_01_2 = {63 68 69 73 65 6c 2d 63 68 75 6e 6b 65 64 63 6f 6d 6d 61 6e 64 } //01 00  chisel-chunkedcommand
		$a_01_3 = {73 65 6e 64 63 68 69 73 65 6c } //01 00  sendchisel
		$a_01_4 = {43 48 49 53 45 4c 5f 4b 45 59 } //01 00  CHISEL_KEY
		$a_01_5 = {63 68 69 73 65 6c 2e 70 69 64 } //00 00  chisel.pid
	condition:
		any of ($a_*)
 
}