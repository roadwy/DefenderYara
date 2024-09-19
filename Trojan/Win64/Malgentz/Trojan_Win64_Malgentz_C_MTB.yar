
rule Trojan_Win64_Malgentz_C_MTB{
	meta:
		description = "Trojan:Win64/Malgentz.C!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f 28 ca 0f 28 ee 0f c6 ee 55 f3 0f 59 cd 0f 28 c7 f3 0f 59 c6 f3 0f 58 c8 41 0f 28 c0 0f 28 e6 0f c6 e6 aa f3 0f 59 c4 f3 0f 58 c8 41 0f 28 c1 0f 28 de 0f c6 de ff f3 0f 59 c3 f3 0f 58 c8 0f 57 c0 f3 0f 5a c1 f2 0f 11 45 20 41 0f 28 d2 41 0f c6 d2 55 f3 0f 59 d5 0f 28 c7 0f c6 c7 55 f3 0f 59 c6 f3 0f 58 d0 41 0f 28 c8 41 0f c6 c8 55 f3 0f 59 cc f3 0f 58 d1 41 0f 28 c1 41 0f c6 c1 55 f3 0f 59 c3 f3 0f 58 d0 0f 57 c0 f3 0f 5a c2 f2 0f 11 45 b0 45 0f c6 d2 aa f3 44 0f 59 d5 0f c6 ff aa f3 0f 59 fe f3 44 0f 58 d7 45 0f c6 c0 aa f3 44 0f 59 c4 f3 45 0f 58 d0 45 0f c6 c9 aa f3 44 0f 59 cb f3 45 0f 58 d1 0f 57 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}