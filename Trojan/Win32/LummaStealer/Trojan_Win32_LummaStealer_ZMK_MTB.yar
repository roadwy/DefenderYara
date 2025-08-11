
rule Trojan_Win32_LummaStealer_ZMK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZMK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 53 94 d8 6a 4f c4 05 0b c6 d2 e0 af ba a8 2b c5 64 2f 2f c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}