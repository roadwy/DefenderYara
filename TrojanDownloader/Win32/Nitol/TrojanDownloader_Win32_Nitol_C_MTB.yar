
rule TrojanDownloader_Win32_Nitol_C_MTB{
	meta:
		description = "TrojanDownloader:Win32/Nitol.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e8 4b c6 45 e9 65 c6 45 ea 72 c6 45 eb 6e c6 45 ec 65 c6 45 ed 6c c6 45 ee 33 c6 45 ef 32 c6 45 f0 2e c6 45 f1 64 c6 45 f2 6c c6 45 f3 6c } //2
		$a_01_1 = {c6 45 b8 56 c6 45 b9 69 c6 45 ba 72 c6 45 bb 74 c6 45 bc 75 c6 45 bd 61 c6 45 be 6c c6 45 bf 41 c6 45 c0 6c c6 45 c1 6c c6 45 c2 6f c6 45 c3 63 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}