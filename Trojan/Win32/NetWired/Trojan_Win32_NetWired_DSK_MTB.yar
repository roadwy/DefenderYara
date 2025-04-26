
rule Trojan_Win32_NetWired_DSK_MTB{
	meta:
		description = "Trojan:Win32/NetWired.DSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a d1 80 f2 04 88 14 01 41 81 f9 00 e1 f5 05 72 } //1
		$a_01_1 = {69 71 41 32 76 62 58 46 5a 75 55 46 6a 44 48 32 43 } //1 iqA2vbXFZuUFjDH2C
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}