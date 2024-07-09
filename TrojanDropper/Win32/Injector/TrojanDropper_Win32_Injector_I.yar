
rule TrojanDropper_Win32_Injector_I{
	meta:
		description = "TrojanDropper:Win32/Injector.I,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 0c 60 8b 4d ?? 03 c8 89 4d ?? 8b 45 ?? d1 e0 89 45 } //2
		$a_03_1 = {f7 75 14 8b 45 0c 0f b6 04 ?? 03 ?? 99 b9 00 ?? ?? 00 f7 f9 89 55 } //2
		$a_03_2 = {ff 6b c6 85 ?? ?? ff ff 43 c6 85 ?? ?? ff ff 5a c6 85 ?? ?? ff ff 56 c6 85 ?? ?? ff ff 47 } //1
		$a_03_3 = {ff 70 50 8b 85 ?? ?? ff ff ff 70 34 ff 75 ?? ff 95 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}