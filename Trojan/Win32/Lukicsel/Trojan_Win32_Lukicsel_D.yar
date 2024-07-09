
rule Trojan_Win32_Lukicsel_D{
	meta:
		description = "Trojan:Win32/Lukicsel.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {32 06 88 07 46 47 4b 75 f2 90 09 05 00 e8 } //1
		$a_03_1 = {8b d8 6a 00 8d 45 ec 50 6a 04 8d 45 f8 90 09 28 00 b8 ?? ?? ?? ?? 89 45 f4 b8 ?? ?? ?? ?? 89 45 f0 } //2
		$a_03_2 = {6b 62 64 61 74 61 74 ?? 2e 64 6c 6c 00 6b 62 64 } //2
		$a_03_3 = {85 f6 72 17 46 33 ff 53 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 74 05 43 47 4e 75 ec 81 ff e8 03 00 00 75 04 33 db eb 06 } //3
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*3) >=3
 
}