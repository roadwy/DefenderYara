
rule Trojan_Win32_LummaStealer_ZZD_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZZD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 24 c3 78 8f 20 2f 5c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}