
rule Trojan_Win32_LummaC_KK_MTB{
	meta:
		description = "Trojan:Win32/LummaC.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 54 24 14 8b 4c 24 14 0f b6 05 ?? ?? ?? 00 02 c1 a2 ?? ?? ?? 00 0f b6 04 16 42 8a 0d ?? ?? ?? 00 32 c8 88 0d ?? ?? ?? 00 80 3c 16 00 } //20
		$a_01_1 = {32 14 28 41 30 14 1e 47 43 89 4c 24 44 8b 8c 24 98 00 00 00 81 fb 00 01 00 00 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}