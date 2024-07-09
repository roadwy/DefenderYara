
rule TrojanDropper_Win32_NukeSped_PI_MTB{
	meta:
		description = "TrojanDropper:Win32/NukeSped.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 f9 10 72 03 83 e9 ?? 8a 04 3a 32 44 0d e0 42 88 44 13 ef 41 3b d6 72 } //1
		$a_03_1 = {68 00 10 00 00 51 03 c3 50 ff ?? ?? ?? ?? ?? 85 c0 74 ?? 8b 46 04 ff 36 03 45 ?? 8b 7e fc 03 fb 50 57 e8 ?? ?? ?? ?? 89 7e f8 8b 55 fc 83 c4 0c 8b 45 0c 8b 7d f8 8b 00 47 0f b7 40 06 83 c6 ?? 89 7d f8 3b f8 0f 8c 68 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}