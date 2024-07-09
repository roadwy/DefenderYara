
rule Trojan_Win32_Miuref_R{
	meta:
		description = "Trojan:Win32/Miuref.R,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 6b 09 14 00 74 ?? 8a 0c 16 80 f9 61 7c 0d 80 f9 7a 7f 08 0f be c9 83 e9 20 eb 03 0f be c9 6b c0 1f 03 c1 42 3b d7 72 de } //1
		$a_03_1 = {3d c7 50 58 e8 75 [0-11] c7 05 ?? ?? ?? ?? 01 00 00 00 } //1
		$a_03_2 = {c6 06 7b ff 37 8d 46 01 6a ?? 6a ?? 50 e8 ?? ?? ?? ?? c6 46 09 2d 0f b7 47 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}