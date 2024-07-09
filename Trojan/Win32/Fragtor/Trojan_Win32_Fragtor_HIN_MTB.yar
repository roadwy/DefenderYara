
rule Trojan_Win32_Fragtor_HIN_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.HIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ca 8b c3 0f a4 c1 0d c1 e0 0d 33 d1 8b 4c 24 10 33 d8 8b c3 0f ac d0 ?? 32 c3 30 04 0f 41 89 4c 24 ?? 83 f9 0e 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}