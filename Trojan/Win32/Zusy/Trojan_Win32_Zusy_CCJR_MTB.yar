
rule Trojan_Win32_Zusy_CCJR_MTB{
	meta:
		description = "Trojan:Win32/Zusy.CCJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e4 65 c6 45 e5 72 c6 45 e6 72 c6 45 e7 6f c6 45 e8 72 c6 45 e9 3a c6 45 ea 30 c6 45 eb 78 c6 45 ec 43 c6 45 ed 30 c6 45 ee 30 c6 45 ef 30 c6 45 f0 30 c6 45 f1 30 c6 45 f2 30 c6 45 f3 35 c6 45 f4 00 } //2
		$a_01_1 = {c6 45 f8 49 c6 45 f9 4f c6 45 fa 56 c6 45 fb 41 c6 45 fc 53 c6 45 fd 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}