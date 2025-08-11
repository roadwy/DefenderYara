
rule Trojan_Win32_LummaStealer_ZIK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZIK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 c7 44 24 28 10 00 00 00 48 89 74 24 20 48 c7 44 24 30 10 00 00 00 b8 ab 90 92 6d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}