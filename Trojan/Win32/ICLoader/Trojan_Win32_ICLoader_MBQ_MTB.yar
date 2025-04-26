
rule Trojan_Win32_ICLoader_MBQ_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.MBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 6a ff 68 ?? ?? 60 00 68 ?? ?? 60 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 60 00 33 d2 8a d4 89 15 ?? ?? ?? 00 8b c8 81 e1 } //2
		$a_01_1 = {33 f6 56 e8 16 0b 00 00 59 85 c0 75 08 6a 1c e8 b0 00 00 00 59 89 75 fc } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}