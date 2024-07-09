
rule TrojanDownloader_Win32_Harnig_S{
	meta:
		description = "TrojanDownloader:Win32/Harnig.S,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2e 70 68 70 3f 61 64 76 3d } //1 .php?adv=
		$a_00_1 = {26 63 6f 64 65 31 3d 25 73 26 63 6f 64 65 32 3d 25 73 26 69 64 3d 25 64 26 70 3d 25 73 } //1 &code1=%s&code2=%s&id=%d&p=%s
		$a_03_2 = {ff d6 8a 45 ?? 04 1d 88 45 ?? 8a 45 ?? 83 c4 0c 3a c3 75 06 c6 45 ?? 30 eb 05 04 13 88 45 ?? 0f b7 45 ?? 50 8d 45 ?? 68 ?? ?? ?? ?? 50 ff d6 8a 45 ?? 04 17 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}