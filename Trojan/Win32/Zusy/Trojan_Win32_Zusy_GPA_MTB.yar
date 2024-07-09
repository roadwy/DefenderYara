
rule Trojan_Win32_Zusy_GPA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 81 c2 36 ed ff ff 89 15 ?? ?? ?? ?? 30 c8 0f b6 c0 5d } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}
rule Trojan_Win32_Zusy_GPA_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 d0 03 55 f8 0f b6 02 83 f0 57 8b 4d e4 03 4d f8 88 01 eb 52 8b 45 f8 33 d2 b9 03 00 00 00 f7 f1 83 fa 01 75 16 8b 55 d0 03 55 f8 0f b6 02 83 f0 77 8b 4d e4 03 4d f8 88 01 eb 2b 8b 45 f8 33 d2 b9 03 00 00 00 f7 f1 83 fa 02 75 1a 8b 55 d0 03 55 f8 0f b6 02 83 f0 36 0f b6 4d f8 33 c1 8b 55 e4 03 55 f8 88 02 e9 72 ff ff ff } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}