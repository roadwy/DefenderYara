
rule VirTool_Win64_Mowelesz_A{
	meta:
		description = "VirTool:Win64/Mowelesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 41 53 41 52 41 51 41 50 51 41 ff 73 28 52 41 ff 73 20 48 83 ec 28 41 ff 73 30 48 83 ec 28 41 ff 73 30 41 ff 73 10 } //1
		$a_01_1 = {48 89 84 24 20 05 00 00 c6 84 24 a8 00 00 00 4d c6 84 24 a9 00 00 00 79 c6 84 24 aa 00 00 00 54 c6 84 24 ab 00 00 00 65 c6 84 24 ac 00 00 00 73 c6 84 24 ad 00 00 00 74 c6 84 24 ae 00 00 00 31 c6 84 24 af } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}