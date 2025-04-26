
rule Trojan_Win32_Stealer_DAC_MTB{
	meta:
		description = "Trojan:Win32/Stealer.DAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 9c c1 20 e2 20 c1 08 ca 88 e1 30 c4 20 c1 08 cc b9 ?? ?? ?? ?? 88 e0 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}