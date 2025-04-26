
rule Trojan_Win32_Graftor_BAC_MTB{
	meta:
		description = "Trojan:Win32/Graftor.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 d1 80 c1 42 80 f1 a3 80 c1 4b 80 f1 e7 88 8c 1d ?? ?? ?? ?? 83 c3 01 eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}