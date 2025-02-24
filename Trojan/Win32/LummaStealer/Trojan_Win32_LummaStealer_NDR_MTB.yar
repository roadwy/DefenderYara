
rule Trojan_Win32_LummaStealer_NDR_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 df 30 f9 34 ff 88 cd 30 c5 20 cd 88 f0 34 ff 24 01 8a 4d e3 80 f1 01 88 f3 20 cb 8a 7d e3 80 f7 01 80 e7 ff 80 e1 01 08 d8 08 cf 30 f8 } //2
		$a_01_1 = {88 c2 80 f2 ff 80 e2 01 b4 01 88 e5 80 f5 01 88 c6 20 ee 08 f2 80 f2 ff 80 f2 01 80 e2 ff 88 e5 80 f5 01 80 e5 01 88 e6 80 f6 01 88 f3 80 e3 01 88 e7 80 f7 01 80 e7 ff } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}