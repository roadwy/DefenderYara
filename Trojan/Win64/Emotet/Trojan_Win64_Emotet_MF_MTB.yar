
rule Trojan_Win64_Emotet_MF_MTB{
	meta:
		description = "Trojan:Win64/Emotet.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {41 f7 e8 c1 fa 02 8b c2 c1 e8 1f 03 d0 41 8b c0 41 ff c0 8d 0c 52 c1 e1 03 2b c1 48 63 c8 48 8d 05 90 01 04 8a 04 01 42 32 04 0f 41 88 01 49 ff c1 44 3b c6 72 90 00 } //10
		$a_01_1 = {b8 9d 82 97 53 48 ff c5 f7 e6 8b c6 ff c6 c1 ea 04 6b d2 31 2b c2 48 63 c8 42 0f b6 04 39 41 32 44 2e ff 88 45 ff 41 3b f5 0f 82 } //10
		$a_03_2 = {4c 8b c8 48 2b f8 41 8b c0 41 83 c0 01 99 83 e2 1f 03 c2 83 e0 1f 2b c2 48 63 c8 48 8d 05 90 01 04 8a 04 01 42 32 04 0f 41 88 01 49 83 c1 01 44 3b c6 72 90 00 } //10
		$a_01_3 = {b8 89 88 88 88 49 ff c1 41 f7 e0 41 8b c0 41 ff c0 c1 ea 03 6b d2 0f 2b c2 48 63 c8 42 0f b6 04 11 41 32 44 29 ff 41 88 41 ff 45 3b c4 72 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*10) >=10
 
}