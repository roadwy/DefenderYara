
rule Trojan_Win32_LummaStealer_ALR_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ALR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 da 88 f8 08 ef 80 e5 1f 24 1f 08 ec f6 d7 08 c1 30 cc 08 e7 8a 64 24 03 88 e0 20 f0 30 e6 08 c6 88 f8 f6 d0 20 f0 f6 d6 20 fe 08 c6 89 d0 80 e2 40 f6 d0 24 bf 08 c2 88 f0 80 f2 40 20 d0 30 f2 08 c2 b8 31 d4 6a ea 88 14 37 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}