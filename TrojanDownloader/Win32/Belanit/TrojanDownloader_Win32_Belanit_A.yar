
rule TrojanDownloader_Win32_Belanit_A{
	meta:
		description = "TrojanDownloader:Win32/Belanit.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {61 00 68 00 6d 00 65 00 74 00 } //1 ahmet
		$a_01_1 = {3d 4d 5a 00 00 0f 85 f0 02 00 00 8b 45 c8 6a 04 5e 83 c0 3c 56 0f 80 5a 03 00 00 50 e8 f2 fe ff ff 8b d8 56 03 5d c8 0f 80 48 03 00 00 53 e8 e0 fe ff ff 3d 50 45 00 00 0f 85 bd 02 00 00 8b c3 56 83 c0 34 0f 80 2b 03 00 00 } //1
		$a_00_2 = {66 00 6f 00 78 00 2e 00 65 00 78 00 65 00 } //1 fox.exe
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}