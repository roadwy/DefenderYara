
rule Spammer_Win32_Tedroo_I{
	meta:
		description = "Spammer:Win32/Tedroo.I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {85 f6 76 08 30 04 08 40 3b c6 72 f8 33 c0 85 f6 76 08 30 04 08 40 3b c6 72 f8 4a 75 e1 } //1
		$a_03_1 = {8a c8 80 c1 ?? 30 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 72 ed be ?? ?? ?? ?? 8d 7d e8 a5 a5 a5 a5 b8 ?? ?? ?? ?? 8b f0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}