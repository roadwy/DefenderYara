
rule Trojan_Win32_Farfli_CCGE_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CCGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 ec 4b c6 45 ed 45 c6 45 ee 52 c6 45 ef 4e c6 45 f0 45 c6 45 f1 4c c6 45 f2 33 c6 45 f3 32 c6 45 f4 2e c6 45 f5 64 c6 45 f6 6c c6 45 f7 6c 88 5d f8 c6 45 d0 43 c6 45 d1 72 c6 45 d2 65 c6 45 d3 61 c6 45 d4 74 c6 45 d5 65 c6 45 d6 54 c6 45 d7 6f c6 45 d8 6f c6 45 d9 6c c6 45 da 68 c6 45 db 65 c6 45 dc 6c c6 45 dd 70 c6 45 de 33 c6 45 df 32 c6 45 e0 53 c6 45 e1 6e c6 45 e2 61 c6 45 e3 70 c6 45 e4 73 c6 45 e5 68 c6 45 e6 6f c6 45 e7 74 } //00 00 
	condition:
		any of ($a_*)
 
}