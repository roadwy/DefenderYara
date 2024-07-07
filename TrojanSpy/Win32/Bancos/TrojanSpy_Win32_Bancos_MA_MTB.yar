
rule TrojanSpy_Win32_Bancos_MA_MTB{
	meta:
		description = "TrojanSpy:Win32/Bancos.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {e5 d5 4a 02 a5 90 01 04 99 ea 90 01 04 3b 00 90 00 } //1
		$a_03_1 = {ff cc 31 00 06 8b 1c d4 4d e0 90 01 01 97 46 a0 90 01 04 36 41 88 e5 a3 90 01 04 bc 90 01 04 d5 10 b1 ba b7 3a 4f ad 33 99 90 01 04 0c 00 aa 00 60 d3 93 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}