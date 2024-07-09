
rule Trojan_Win32_Vidar_PL_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c8 8b 85 ?? ?? ?? ?? 33 d2 f7 f1 8b 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 8a 04 02 32 04 31 88 06 } //1
		$a_03_1 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ?? 33 c2 83 c1 04 a9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}