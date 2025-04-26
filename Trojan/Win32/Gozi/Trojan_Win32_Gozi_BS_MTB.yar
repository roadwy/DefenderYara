
rule Trojan_Win32_Gozi_BS_MTB{
	meta:
		description = "Trojan:Win32/Gozi.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c3 2b c6 83 c0 b5 03 d0 0f b7 c1 03 c7 3d 91 01 00 00 75 0f 8b c6 83 c1 13 2b c2 03 05 ?? ?? ?? ?? 03 c8 8b c6 2b c1 8b 0d ?? ?? ?? ?? 03 c2 83 c2 0e 0f b7 f8 } //1
		$a_02_1 = {8b cf 83 c2 b5 2b c1 03 d0 8d 5a cb 03 d9 89 1d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 83 44 24 10 04 2b cf 8b 7c 24 14 03 ca ff 4c 24 18 0f b7 c9 0f } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}