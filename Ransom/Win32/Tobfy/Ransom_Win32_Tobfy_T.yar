
rule Ransom_Win32_Tobfy_T{
	meta:
		description = "Ransom:Win32/Tobfy.T,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c0 c6 45 e8 50 c6 45 e9 72 c6 45 ea 6f c6 45 eb 67 c6 45 ec 72 c6 45 ed 61 c6 45 ee 6d c6 45 ef 20 c6 45 f0 4d c6 45 f1 61 c6 45 f2 6e c6 45 f3 61 c6 45 f4 67 c6 45 f5 65 c6 45 f6 72 8d 7d f7 ab 66 ab aa } //1
		$a_03_1 = {50 6a 01 ff 15 90 01 04 8b f0 85 f6 74 0c 6a ff 56 ff 15 90 01 04 56 ff d7 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}