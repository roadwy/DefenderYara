
rule TrojanDownloader_Win32_Nymaim_I{
	meta:
		description = "TrojanDownloader:Win32/Nymaim.I,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 75 08 c3 90 09 0c 00 8d 15 ?? ?? ?? ?? 52 68 } //8
		$a_03_1 = {33 ff 8d b4 7d ?? ff ff ff 0f b7 ?? [0-01] e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b c7 99 6a 19 59 f7 f9 8d 42 61 66 89 06 0f b7 c0 50 e8 ?? ?? ?? ?? [0-04] a3 90 1b 04 83 ff 40 72 } //1
		$a_03_2 = {33 f6 8d 8c 75 ?? ff ff ff 0f b7 ?? [0-01] e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? [0-03] 8b c6 99 6a 19 5f f7 ff 8d 42 61 66 89 01 0f b7 [0-02] e8 ?? ?? ?? ?? [0-03] 46 a3 90 1b 04 83 fe 40 72 } //1
		$a_03_3 = {33 f6 8d 4c 35 ?? 0f be 01 [0-01] e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b c6 99 6a 19 5f f7 ff 80 c2 61 0f be c2 50 88 11 e8 ?? ?? ?? ?? 46 59 [0-01] a3 90 1b 03 83 fe 40 72 } //1
	condition:
		((#a_03_0  & 1)*8+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=9
 
}