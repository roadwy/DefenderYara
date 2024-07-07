
rule Trojan_Win32_Emotet_DAB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c1 bd 36 00 00 00 f7 f5 8a 04 53 30 04 31 41 3b cf 75 ea } //1
		$a_01_1 = {8b c6 2b c2 d1 e8 03 c2 8b 54 24 14 c1 e8 05 6b c0 36 8b ce 2b c8 8a 04 4a 30 04 1e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}