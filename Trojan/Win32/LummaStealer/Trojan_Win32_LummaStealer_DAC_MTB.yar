
rule Trojan_Win32_LummaStealer_DAC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c1 83 f1 7e 83 e0 01 01 c0 29 c8 8b 4c 24 0c 04 89 88 01 46 41 83 c2 02 83 fa 08 0f 85 35 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}