
rule VirTool_Win64_PrivEscDcom_A{
	meta:
		description = "VirTool:Win64/PrivEscDcom.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {f3 48 a5 4c 89 e1 48 8b 74 24 f8 48 8b 7c 24 f0 4c 8b 64 24 e8 ff } //1
		$a_01_1 = {4c 8b 7b 08 48 89 7c 24 38 c7 44 24 30 7b 00 00 00 83 64 24 28 00 c7 44 24 20 09 02 00 00 4c 89 f9 ba 03 00 00 00 45 31 c0 41 b9 ff 00 00 00 e8 } //1
		$a_01_2 = {44 3a 28 41 3b 4f 49 43 49 3b 47 41 3b 3b 3b 57 44 29 } //1 D:(A;OICI;GA;;;WD)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}