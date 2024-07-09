
rule Worm_Win32_Cridex_C{
	meta:
		description = "Worm:Win32/Cridex.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 81 ec 2c 04 00 00 56 57 53 68 00 04 00 00 8d 85 d4 fb ff ff 50 ff 15 ?? ?? ?? 00 0f b6 85 d4 fb ff ff 85 c0 0f 84 ?? ?? ?? ?? 8d 85 d4 fb ff ff 50 68 00 04 00 00 ff 15 ?? ?? ?? 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 } //1
		$a_01_1 = {8b 45 f8 89 45 d4 ff 55 d4 5b 5f 5e 89 ec 5d c2 10 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}