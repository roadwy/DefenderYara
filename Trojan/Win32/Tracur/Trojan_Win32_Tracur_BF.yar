
rule Trojan_Win32_Tracur_BF{
	meta:
		description = "Trojan:Win32/Tracur.BF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 4a 2c 3d fe fe fe fe 75 1c b8 ?? ?? ?? ?? 89 45 fc 8b d3 8d 45 fc b9 04 00 00 00 } //1
		$a_01_1 = {83 fa 50 72 46 60 8b 7d fc 31 c0 0f a2 ab 93 ab 91 ab 92 ab 31 c0 40 0f a2 } //1
		$a_03_2 = {8b 53 18 81 7c 82 24 00 14 00 00 0f 82 ?? ?? ?? ?? 8d 4d f8 8b d6 8b c3 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}