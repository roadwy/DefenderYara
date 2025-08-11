
rule Trojan_Win32_Lazy_AD_MTB{
	meta:
		description = "Trojan:Win32/Lazy.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 83 e0 0f 8a 80 f8 e0 42 00 30 81 10 1b 43 00 8d ?? 10 1b 43 00 03 c1 83 e0 0f 8a 80 f8 e0 42 00 30 81 11 1b 43 00 8d ?? 10 1b 43 00 03 c1 83 e0 0f 8a 80 f8 e0 42 00 30 81 12 1b 43 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}