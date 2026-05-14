
rule Ransom_Win32_Filecoder_SXF_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.SXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e0 0f c6 45 e1 ba c6 45 e2 ff c6 45 e3 0d c6 45 e4 0f c6 45 e5 a4 c6 45 e6 f7 c6 45 e7 dd c6 45 e8 47 c6 45 e9 f7 c6 45 ea c0 c6 45 eb 7d c6 45 ec 4c c6 45 ed df c6 45 ee 26 c6 45 ef 0f c6 45 f0 a5 c6 45 f1 c1 c6 45 f2 c3 } //20
		$a_01_1 = {8b 51 3c 8b 45 08 8d 4c 10 04 89 4d ec 8b 55 ec 83 c2 14 89 55 e8 b8 08 00 00 00 6b c8 00 8b 55 e8 8b 44 0a 60 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}