
rule Trojan_Win32_LummaStealer_ZJK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZJK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 28 3b 82 87 c3 08 c6 2e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}