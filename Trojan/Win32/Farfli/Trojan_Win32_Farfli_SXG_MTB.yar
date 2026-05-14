
rule Trojan_Win32_Farfli_SXG_MTB{
	meta:
		description = "Trojan:Win32/Farfli.SXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 bd 70 c6 45 be 70 c6 45 bf 6c c6 45 c0 69 c6 45 c1 63 c6 45 c2 61 c6 45 c3 74 c6 45 c4 69 c6 45 c5 6f c6 45 c6 6e c6 45 c7 73 } //30
		$a_01_1 = {c6 45 ed 69 c6 45 ee 6e c6 45 ef 53 c6 45 f0 74 c6 45 f1 61 c6 45 f2 30 c6 45 f3 5c c6 45 f4 44 c6 45 f5 65 c6 45 f6 66 c6 45 f7 61 c6 45 f8 75 c6 45 f9 6c c6 45 fa 74 88 5d fb } //10
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*10) >=40
 
}