
rule TrojanDownloader_Win32_Bedobot_C{
	meta:
		description = "TrojanDownloader:Win32/Bedobot.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_02_0 = {2e 6d 61 69 00 [0-10] 2e 65 6d 6c 00 [0-10] 2e 74 62 62 00 [0-10] 2e 6d 62 6f 78 00 } //1
		$a_01_1 = {2e 70 68 70 3f 49 3d 31 00 } //1
		$a_03_2 = {74 1a 8d 4d ?? 8b d3 8b 45 ?? 8b 38 ff 57 ?? 8b 55 ?? b1 06 8b 45 ?? e8 ?? ?? ?? ?? 43 4e 0f 85 ?? ?? ff ff } //2
		$a_03_3 = {75 0d 8d 45 ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 ?? 8b 45 ?? e8 ?? ?? ?? ?? 48 0f 85 ?? ?? ?? ?? 80 7d ?? 01 75 04 b3 02 eb 02 } //2
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=5
 
}