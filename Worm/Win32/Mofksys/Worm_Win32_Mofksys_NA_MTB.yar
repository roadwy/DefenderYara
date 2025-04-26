
rule Worm_Win32_Mofksys_NA_MTB{
	meta:
		description = "Worm:Win32/Mofksys.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 88 0a c3 0f b7 08 66 89 0a c3 66 8b 08 8a 40 ?? 66 89 0a 88 42 ?? c3 8b 08 89 0a c3 } //1
		$a_03_1 = {8b c7 b9 4e 00 00 00 99 f7 f9 58 2b c2 b9 ?? 00 00 00 99 f7 f9 8b c8 49 6b c1 ?? 50 8b 45 ?? 5a 2b c2 83 e8 ?? be ?? 00 00 00 99 f7 fe 8b f0 } //1
		$a_03_2 = {3d 13 20 00 00 0f 8f be 00 00 00 0f 84 62 02 00 00 3d ?? ?? 00 00 7f 5e 0f 84 ce 01 00 00 3d ?? 00 00 00 7f 2f 0f 84 09 02 00 00 83 e8 ?? 0f 84 34 01 00 00 83 e8 ?? 0f 84 43 01 00 00 83 e8 ?? 0f 84 ca 01 00 00 83 e8 ?? 0f 84 d9 01 00 00 e9 79 02 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}