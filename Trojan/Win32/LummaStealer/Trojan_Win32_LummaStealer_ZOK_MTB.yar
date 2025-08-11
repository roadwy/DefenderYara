
rule Trojan_Win32_LummaStealer_ZOK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZOK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {51 49 52 49 53 49 54 49 55 49 56 49 57 e8 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}