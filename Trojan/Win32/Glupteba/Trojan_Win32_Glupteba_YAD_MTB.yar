
rule Trojan_Win32_Glupteba_YAD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 05 03 44 24 ?? 03 ?? 33 c2 33 c1 2b f0 8b d6 c1 e2 04 89 44 24 14 c7 05 ?? ?? ?? ?? 00 00 00 00 89 54 24 0c 8b 44 24 28 01 44 24 0c 81 3d ?? ?? ?? ?? be 01 00 00 8d 3c 33 } //1
		$a_03_1 = {8b c1 c1 e8 05 03 44 24 ?? 03 d5 33 c2 03 cb 33 c1 2b f0 8b d6 c1 e2 04 89 44 24 ?? c7 05 ?? ?? ?? ?? 00 00 00 00 89 54 24 ?? 8b 44 24 28 01 44 24 10 81 3d ?? ?? ?? ?? be 01 00 00 8d 3c 33 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}