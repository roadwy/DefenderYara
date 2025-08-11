
rule Trojan_Win32_LummaStealer_ZGK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZGK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 fe 89 d5 21 fd 31 d7 01 f7 29 f7 29 f7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}