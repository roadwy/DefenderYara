
rule Trojan_Win32_GCleaner_CC_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 0b ff d7 6a 0c 8b d8 ff d7 8b 4e 20 8b f8 8d 44 24 10 50 51 ff 15 68 55 48 00 8b 44 24 1c 2b 44 24 14 8b 56 74 2b c7 40 52 99 2b c2 d1 f8 50 8b 44 24 20 2b 44 24 } //2
		$a_01_1 = {e8 96 ed ff ff 85 c0 74 1e 68 f0 c9 49 00 8d 54 24 18 52 8d 44 24 20 50 e8 4e 2a 00 00 83 c4 0c c6 44 24 24 02 eb 1c 68 1c ca 49 } //2
		$a_01_2 = {d6 9e 74 0e a5 e4 e6 fc 43 35 7a 0c 6d 20 15 a6 68 37 b3 bb 28 b7 67 62 4e 34 48 61 4b 71 f5 0a } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}