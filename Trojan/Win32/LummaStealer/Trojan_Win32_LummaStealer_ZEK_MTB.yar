
rule Trojan_Win32_LummaStealer_ZEK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZEK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 09 cb 89 e9 83 c9 fe 31 d9 89 cb 81 f3 14 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}