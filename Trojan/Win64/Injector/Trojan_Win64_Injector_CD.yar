
rule Trojan_Win64_Injector_CD{
	meta:
		description = "Trojan:Win64/Injector.CD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 0f b6 ca 45 0f b6 c2 41 8d 41 fc 48 63 d0 0f b6 04 0a 41 30 04 08 45 8d 41 01 41 8d 41 fd 48 63 d0 0f b6 04 0a 41 30 04 08 41 8d 41 fe 48 63 d0 45 8d 41 02 0f b6 04 0a 41 30 04 08 41 8d 41 ff 48 63 d0 45 8d 41 03 0f b6 04 0a 41 30 04 08 41 80 c2 fc 75 aa } //1
		$a_01_1 = {0f b6 17 48 8b 5c 24 08 0f b6 c2 24 01 f6 d8 0f b6 41 1d 45 1a c0 d0 ea 41 80 e0 8d 44 32 c2 42 0f b6 14 18 0f b6 41 1e 41 32 d0 30 11 44 88 07 48 8b 7c 24 10 42 0f b6 04 18 30 41 01 0f b6 41 1f 42 0f b6 04 18 30 41 02 0f b6 41 1c 42 0f b6 04 18 30 41 03 c3 } //1
		$a_03_2 = {48 89 5c 24 08 44 0f b6 02 48 8d 1d ?? ?? ?? ?? 0f b6 41 1d 4c 8d 59 04 4c 8b ca 41 b2 04 0f b6 04 18 41 32 c0 30 01 0f b6 41 1e 0f b6 04 18 30 41 01 0f b6 41 1f 0f b6 04 18 30 41 02 0f b6 41 1c 0f b6 04 18 30 41 03 41 0f b6 c0 c0 e8 07 45 02 c0 0f b6 c0 6b d0 1b 41 32 d0 41 88 11 66 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}