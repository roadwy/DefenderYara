
rule Trojan_Win32_LummaStealer_DMP_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c3 89 de 83 e6 01 89 f1 f7 d9 81 f6 01 01 01 01 89 df 81 e7 fe 00 00 00 0f af fe } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}