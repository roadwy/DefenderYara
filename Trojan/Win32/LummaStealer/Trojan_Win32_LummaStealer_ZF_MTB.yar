
rule Trojan_Win32_LummaStealer_ZF_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZF!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 72 9a e0 e8 07 e2 97 33 4f 15 ed 85 87 24 ba 81 aa 59 39 c2 20 d9 81 5f d9 cb f2 95 b4 50 ab 7e 7c 29 3e 55 54 74 e9 9b 64 cb a8 8c 95 38 79 e9 3e 4b 06 c3 ee 14 46 08 c6 0c cb 6b 79 d6 8d 50 5b 45 1f 88 48 c8 62 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}