
rule Trojan_Win32_LummaStealer_ZZC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZZC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {77 45 d8 b1 3b f8 7f 3c eb d6 bc 73 5f 61 84 c2 65 d2 ab c3 b5 5d 60 1e 05 f6 6d 1d 07 4f 44 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}