
rule Trojan_Win32_LummaStealer_ZBK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZBK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 04 19 25 22 23 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}