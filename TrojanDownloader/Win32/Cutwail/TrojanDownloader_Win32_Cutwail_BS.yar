
rule TrojanDownloader_Win32_Cutwail_BS{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.BS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {b9 ff ff 00 00 53 e8 90 01 04 3d 90 01 04 75 90 01 01 89 9d 90 01 02 ff ff 43 e2 90 01 01 61 83 bd 90 1b 03 00 0f 84 90 01 01 00 00 00 90 00 } //1
		$a_03_1 = {b9 ff ff 00 00 53 e8 90 01 04 3d 90 01 04 75 90 01 01 89 5d 90 01 01 43 e2 90 01 01 61 83 7d 90 1b 03 00 74 90 00 } //1
		$a_03_2 = {c1 e9 02 8b 35 90 01 04 81 c6 ca 01 00 00 8b fe 8b 85 90 01 02 ff ff bb 90 01 04 33 d2 81 c3 90 01 02 00 00 f7 e3 05 90 01 04 50 8f 85 90 01 02 ff ff ad 33 85 90 01 02 ff ff ab e2 d5 90 00 } //1
		$a_03_3 = {c1 e9 02 8b 35 90 01 04 81 c6 ca 01 00 00 8b fe 8b 45 90 01 01 bb 90 01 04 33 d2 f7 e3 05 90 01 04 89 45 90 01 01 ad 33 45 90 01 01 ab e2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}