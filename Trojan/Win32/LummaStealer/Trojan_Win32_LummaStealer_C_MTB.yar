
rule Trojan_Win32_LummaStealer_C_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {21 c8 01 c0 89 c1 31 d1 f7 d0 21 d0 01 c0 29 c8 89 c1 83 c9 90 01 01 83 e0 90 01 01 01 c8 fe c0 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}