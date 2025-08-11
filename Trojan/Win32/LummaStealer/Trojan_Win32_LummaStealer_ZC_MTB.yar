
rule Trojan_Win32_LummaStealer_ZC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 54 8d 25 99 09 20 36 1b d1 a0 29 4c 3e 6e a2 8c bd 39 3a 14 06 75 f9 8b 82 4f 8f e6 6c cc 5a 92 9f 58 f3 09 38 c6 62 53 43 87 51 f8 aa e4 e2 9b f7 48 e1 b4 c1 da 21 0e 6d 2b 28 a1 bb 93 36 f4 9c ec 11 8d 7e 82 f5 e3 8f e6 fb 58 0a 33 17 14 71 36 82 b3 fc 5b ee 0d 1c d8 45 3a ea 5b 13 8a 01 9c d7 d2 ae db 2e 87 9e 0b 02 85 c1 14 3c 43 db 02 9f 81 7e 60 f4 7b 6b 7f f6 3e 77 b0 d7 d6 80 c5 07 f9 28 5e 84 c0 69 9c a7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}