
rule TrojanDownloader_Win32_Awavs_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Awavs.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 10 59 6a 04 33 db 58 f7 e1 0f 90 90 c3 89 4f 04 f7 db 0b d8 53 e8 ?? ?? ?? ?? 6a 08 89 47 08 } //1
		$a_03_1 = {f7 d9 1b c9 99 81 e2 ff 01 00 00 03 c2 f7 d9 c1 f8 09 03 c8 c1 e1 09 51 89 0e e8 ?? ?? ?? ?? 8b f8 8b 46 04 } //1
		$a_01_2 = {3c 72 6f 6f 74 3e 3c 67 65 74 5f 6d 6f 64 75 6c 65 20 62 6f 74 6e 65 74 3d 22 25 64 22 20 6e 61 6d 65 3d 22 25 73 22 20 62 69 74 3d } //2 <root><get_module botnet="%d" name="%s" bit=
		$a_01_3 = {63 66 67 00 62 6f 74 6e 65 74 3d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=4
 
}