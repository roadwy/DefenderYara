
rule Trojan_Win32_GCleaner_CC_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {6a 0b ff d7 6a 0c 8b d8 ff d7 8b 4e 20 8b f8 8d 44 24 10 50 51 ff 15 68 55 48 00 8b 44 24 1c 2b 44 24 14 8b 56 74 2b c7 40 52 99 2b c2 d1 f8 50 8b 44 24 20 2b 44 24 } //02 00 
		$a_01_1 = {e8 96 ed ff ff 85 c0 74 1e 68 f0 c9 49 00 8d 54 24 18 52 8d 44 24 20 50 e8 4e 2a 00 00 83 c4 0c c6 44 24 24 02 eb 1c 68 1c ca 49 } //02 00 
		$a_01_2 = {83 c4 04 0b f3 52 c1 e6 08 e8 a1 cb 04 00 8b 4c 24 1c 0f b6 c0 0b c6 89 01 8d 47 f0 83 c4 04 8d 50 0c 83 c9 ff f0 0f c1 0a 49 85 c9 7f 0a 8b 08 8b 11 50 8b 42 04 ff d0 c6 44 24 48 01 8b 44 24 20 83 c0 f0 8d 48 0c 83 ca ff f0 } //02 00 
		$a_01_3 = {8b 4c 24 24 0f b6 f0 83 c4 04 0b f3 51 c1 e6 08 e8 57 c6 04 00 0f b6 d0 8b 44 24 18 83 c4 04 0b d6 89 90 f8 03 00 00 8b 4d 14 8b 55 10 8b 45 0c 51 8b 4d 08 52 50 51 8b 4c 24 24 e8 c1 e3 } //00 00 
	condition:
		any of ($a_*)
 
}