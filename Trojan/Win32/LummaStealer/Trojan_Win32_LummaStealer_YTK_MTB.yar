
rule Trojan_Win32_LummaStealer_YTK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.YTK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 14 10 d1 d2 d3 } //1
		$a_01_1 = {1e 01 de 46 21 d6 01 d7 47 01 f6 29 f7 21 d7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}