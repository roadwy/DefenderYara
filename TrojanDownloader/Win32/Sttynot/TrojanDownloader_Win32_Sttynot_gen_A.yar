
rule TrojanDownloader_Win32_Sttynot_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Sttynot.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 54 1a ff 80 f2 ?? 88 54 18 ff 43 4e 75 e6 } //1
		$a_03_1 = {ba 01 08 00 00 e8 ?? ?? ?? ?? 6a 00 68 01 08 00 00 8d 85 ?? ?? ff ff 50 53 e8 } //1
		$a_01_2 = {3f 73 74 61 74 75 73 3d 61 63 74 69 76 61 74 65 64 26 74 79 70 65 3d 72 75 6e 26 6e 6f 64 65 3d 78 79 7a 26 74 61 73 6b 3d 69 6e 63 6f 6d 70 6c 65 74 65 26 6e 6f 74 69 66 79 3d 74 72 75 65 26 62 72 61 6e 64 3d } //1 ?status=activated&type=run&node=xyz&task=incomplete&notify=true&brand=
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}