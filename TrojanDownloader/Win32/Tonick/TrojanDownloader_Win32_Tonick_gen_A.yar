
rule TrojanDownloader_Win32_Tonick_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Tonick.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 06 00 00 "
		
	strings :
		$a_03_0 = {6b 70 ff fb 12 e7 0b ?? 00 04 00 23 44 ff 2a 31 74 ff 32 04 00 48 ff 44 ff 35 4c ff 00 0c 6b 70 ff f3 ff 00 c6 1c ?? ?? 00 07 f4 01 70 70 ff 1e ?? ?? 00 0b 6b 70 ff f4 01 a9 70 70 ff 00 0a 04 72 ff 64 6c } //10
		$a_03_1 = {66 33 45 d0 0f bf c0 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d c8 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d d8 ff 15 } //10
		$a_00_2 = {43 00 6f 00 64 00 65 00 63 00 20 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 64 00 } //1 Codec Installed
		$a_00_3 = {4d 00 69 00 73 00 73 00 69 00 6e 00 67 00 20 00 43 00 6f 00 64 00 65 00 63 00 20 00 4c 00 6f 00 61 00 64 00 65 00 64 00 } //1 Missing Codec Loaded
		$a_00_4 = {4d 00 69 00 73 00 73 00 69 00 6e 00 67 00 20 00 46 00 69 00 6c 00 65 00 73 00 20 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 64 00 21 00 } //1 Missing Files Installed!
		$a_00_5 = {6a 00 77 00 70 00 75 00 3c 00 28 00 27 00 } //5 jwpu<('
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*5) >=16
 
}