
rule Worm_Win32_Soglueda_A{
	meta:
		description = "Worm:Win32/Soglueda.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {bb 01 00 00 00 bf 20 00 00 00 b8 7a 00 00 00 3b f8 7f 62 } //1
		$a_01_1 = {66 0f b6 14 08 66 b9 ff 00 66 2b ca 0f 80 } //1
		$a_00_2 = {73 00 58 00 65 00 20 00 49 00 6e 00 6a 00 65 00 63 00 74 00 65 00 64 00 2e 00 65 00 78 00 65 00 } //1 sXe Injected.exe
		$a_03_3 = {83 7d c4 02 0f 94 c2 f7 da 66 89 55 c0 8d 45 c8 50 8d 4d cc 51 8d 55 d0 52 6a 03 ff 15 ?? ?? ?? ?? 83 c4 10 0f bf 45 c0 85 c0 74 44 c7 45 fc 08 00 00 00 8b 4d d4 51 8b 55 dc 83 c2 41 0f 80 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}