
rule TrojanDownloader_Win32_Unruy_C{
	meta:
		description = "TrojanDownloader:Win32/Unruy.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 83 f8 58 0f 85 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 0f b6 40 ff 83 f8 50 75 78 a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 0f b6 40 fe 83 f8 55 75 64 } //1
		$a_03_1 = {8b 48 50 51 8b 55 ?? 8b 42 34 } //1
		$a_03_2 = {eb 0d 8b 85 fc fb ff ff 40 89 85 fc fb ff ff 8b 85 fc fb ff ff 3b 85 f0 fb ff ff 73 3b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 9c 0d 00 fc ff ff } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=2
 
}
rule TrojanDownloader_Win32_Unruy_C_2{
	meta:
		description = "TrojanDownloader:Win32/Unruy.C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 "
		
	strings :
		$a_01_0 = {2d 2d 43 4c 49 43 4b 5f 43 59 43 4c 45 53 } //1 --CLICK_CYCLES
		$a_00_1 = {25 73 2e 64 65 6c 6d 65 25 75 } //1 %s.delme%u
		$a_00_2 = {66 61 6b 65 72 5f 76 } //1 faker_v
		$a_00_3 = {25 73 2f 73 65 61 72 63 68 2e 70 68 70 3f 71 3d 25 64 2e 25 64 2e } //1 %s/search.php?q=%d.%d.
		$a_00_4 = {2e 6d 65 67 61 77 65 62 66 69 6e 64 } //1 .megawebfind
		$a_00_5 = {31 32 32 2e 31 34 31 2e 38 36 2e 31 32 } //1 122.141.86.12
		$a_00_6 = {61 64 2d 77 61 74 63 68 } //1 ad-watch
		$a_00_7 = {70 61 76 66 6e 73 76 } //1 pavfnsv
		$a_00_8 = {41 64 6f 62 65 5f 52 65 61 64 65 72 } //1 Adobe_Reader
		$a_01_9 = {52 45 20 57 45 20 47 4f } //1 RE WE GO
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_01_9  & 1)*1) >=8
 
}