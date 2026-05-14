
rule Worm_Win32_Gigex_AGI_MTB{
	meta:
		description = "Worm:Win32/Gigex.AGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 04 01 00 00 ff 35 b8 5b 40 00 e8 ?? ?? ?? ?? 68 04 01 00 00 ff 35 84 5b 40 00 e8 ?? ?? ?? ?? 68 04 01 00 00 ff 35 c0 5b 40 00 e8 ?? ?? ?? ?? 68 db 79 40 00 ff 35 84 5b 40 00 e8 ?? ?? ?? ?? 68 d1 79 40 00 ff 35 c0 5b 40 00 e8 ?? ?? ?? ?? 83 c4 20 68 5d 33 40 00 68 e8 ?? ?? ?? ?? 9a 02 00 00 ff 35 c4 5b 40 00 e8 ?? ?? ?? ?? a3 34 5c 40 00 68 c4 79 40 00 } //2
		$a_01_1 = {49 2d 57 6f 72 6d 2e 47 69 67 75 } //1 I-Worm.Gigu
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}