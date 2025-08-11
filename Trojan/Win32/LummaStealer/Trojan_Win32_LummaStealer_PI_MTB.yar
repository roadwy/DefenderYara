
rule Trojan_Win32_LummaStealer_PI_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b0 40 c3 b0 3f c3 89 c8 04 d0 3c 09 77 06 80 c1 04 89 c8 c3 89 c8 04 bf 3c 1a 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_PI_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 d3 c1 eb 0c 80 e3 3f 80 cb 80 88 5e 01 c1 ea 06 80 e2 3f 80 ca 80 88 56 02 83 e1 3f 89 ca 83 f2 3f 83 f1 7f 09 d1 f6 d1 88 4e 03 b9 04 00 00 00 01 ce e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}