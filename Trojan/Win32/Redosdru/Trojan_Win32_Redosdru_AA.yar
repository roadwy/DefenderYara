
rule Trojan_Win32_Redosdru_AA{
	meta:
		description = "Trojan:Win32/Redosdru.AA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e4 4d c6 45 e5 6f c6 45 e6 7a c6 45 e7 69 c6 45 e8 6c c6 45 e9 6c c6 45 ea 61 c6 45 eb 2f } //1
		$a_03_1 = {80 04 11 7a 03 ca 8b 90 01 02 80 34 11 59 03 ca 42 3b d0 7c e9 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}