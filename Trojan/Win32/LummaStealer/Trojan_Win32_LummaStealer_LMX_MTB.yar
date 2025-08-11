
rule Trojan_Win32_LummaStealer_LMX_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.LMX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e2 14 87 f3 81 e0 b4 6c b8 c1 ff c9 75 c6 f7 d2 0b c4 b9 89 80 f6 70 03 f8 85 cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}