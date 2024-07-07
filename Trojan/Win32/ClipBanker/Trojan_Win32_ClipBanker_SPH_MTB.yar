
rule Trojan_Win32_ClipBanker_SPH_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.SPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 45 ec 54 00 00 00 c7 45 f8 41 00 00 00 c7 45 f4 39 00 00 00 c7 45 f0 7a 00 00 00 c7 45 e8 5a 00 00 00 8d 45 d8 50 ff 15 90 01 04 e8 90 01 04 0f b7 c0 b9 82 00 00 00 99 f7 f9 81 c2 c8 00 00 00 52 ff 15 90 01 04 33 c0 66 89 85 d0 7d ff ff 8d 85 d0 7d ff ff 50 e8 90 01 04 83 c0 e7 59 3d e7 1f 00 00 77 90 00 } //1
		$a_01_1 = {6b 00 64 00 73 00 69 00 71 00 75 00 77 00 65 00 71 00 77 00 } //1 kdsiquweqw
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}