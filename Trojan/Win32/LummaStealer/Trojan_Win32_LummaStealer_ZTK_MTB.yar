
rule Trojan_Win32_LummaStealer_ZTK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZTK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 14 10 d1 d2 d3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}