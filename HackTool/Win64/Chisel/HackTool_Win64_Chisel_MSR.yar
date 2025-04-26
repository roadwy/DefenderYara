
rule HackTool_Win64_Chisel_MSR{
	meta:
		description = "HackTool:Win64/Chisel!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 68 69 73 65 6c 63 6c 69 65 6e 74 } //chiselclient  2
		$a_80_1 = {43 48 49 53 45 4c 5f 43 4f 4e 4e 45 43 54 } //CHISEL_CONNECT  2
		$a_80_2 = {47 6f 20 62 75 69 6c 64 } //Go build  1
		$a_80_3 = {70 6f 77 72 70 72 6f 66 48 } //powrprofH  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}