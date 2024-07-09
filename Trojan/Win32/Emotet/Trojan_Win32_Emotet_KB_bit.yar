
rule Trojan_Win32_Emotet_KB_bit{
	meta:
		description = "Trojan:Win32/Emotet.KB!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 0e 8d 52 08 33 4d f4 8d 76 04 0f b6 c1 43 66 89 42 f8 8b c1 c1 e8 08 0f b6 c0 66 89 42 fa c1 e9 10 0f b6 c1 66 89 42 fc c1 e9 08 0f b6 c1 66 89 42 fe 3b df 72 c9 } //2
		$a_01_1 = {8b 16 8d 49 04 33 55 0c 8d 76 04 88 51 fc 8b c2 c1 e8 08 47 c1 ea 10 88 41 fd 88 51 fe c1 ea 08 88 51 ff 3b fb 72 d9 } //2
		$a_03_2 = {ba 87 82 43 54 b9 ?? ?? ?? 00 e8 ?? ?? ?? ff } //1
		$a_03_3 = {ba 66 5c 89 60 b9 ?? ?? ?? 00 e8 ?? ?? ?? ff } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}