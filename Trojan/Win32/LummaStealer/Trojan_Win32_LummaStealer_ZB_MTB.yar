
rule Trojan_Win32_LummaStealer_ZB_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 cb 10 66 32 c5 10 66 78 ce 03 66 1e 6b 10 66 03 88 04 66 12 af 0f 66 88 83 03 66 bc c8 0e 66 87 69 10 66 d6 c5 10 66 67 90 05 66 00 46 01 66 ef 60 10 66 b8 49 01 66 0d 16 11 66 70 17 04 66 d4 d9 01 66 51 e2 00 66 d4 68 10 66 d3 a7 0f 66 6b a7 0e 66 3e da 01 66 6d d7 01 66 af 0e 0f 66 5a ae 0f 66 a0 d4 0e 66 3a 16 04 66 bb c4 0e 66 f1 d9 00 66 34 c8 0e 66 23 31 0f 66 a8 c6 10 66 23 a3 00 66 b3 68 05 66 ed ee 0f 66 5f 28 04 66 21 9f 0e 66 a5 3f 0f 66 c2 27 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}