
rule Trojan_Win32_LummaStealer_ZVK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZVK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 71 fa 41 a0 46 f0 da 7d de 6a b3 49 e1 cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}