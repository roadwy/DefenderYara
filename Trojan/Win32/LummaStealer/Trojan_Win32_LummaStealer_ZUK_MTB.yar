
rule Trojan_Win32_LummaStealer_ZUK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZUK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1e 01 de 46 21 d6 01 d7 47 01 f6 29 f7 21 d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}