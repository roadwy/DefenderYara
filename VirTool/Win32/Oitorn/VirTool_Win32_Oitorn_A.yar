
rule VirTool_Win32_Oitorn_A{
	meta:
		description = "VirTool:Win32/Oitorn.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 53 30 38 2d 30 36 37 20 45 78 70 6c 6f 69 74 20 66 6f 72 20 43 4e 20 62 79 20 45 4d 4d 40 70 68 34 6e 74 30 6d 2e 6f 72 67 } //1 MS08-067 Exploit for CN by EMM@ph4nt0m.org
		$a_03_1 = {7c c5 b9 06 00 00 00 be 90 01 04 8b fb b8 06 00 00 00 f3 a5 66 a5 8b 15 90 01 04 89 14 2b 83 c5 04 48 75 f1 a1 90 01 04 be 90 01 04 89 04 2b 83 c5 04 8d 0c 2b 83 c5 04 c7 01 48 48 48 48 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}