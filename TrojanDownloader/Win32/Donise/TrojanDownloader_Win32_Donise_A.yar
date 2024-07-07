
rule TrojanDownloader_Win32_Donise_A{
	meta:
		description = "TrojanDownloader:Win32/Donise.A,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 53 50 ff 75 90 01 01 53 e8 90 01 04 85 c0 75 50 8d 85 90 01 04 68 90 01 04 50 ff 15 90 01 04 8b f0 59 3b f3 59 74 36 56 6a 01 8d 45 90 01 01 6a 02 50 ff 15 90 01 04 56 ff 15 90 01 04 83 c4 14 66 81 7d fe 5a 4d 74 1c 66 81 7d fe 4d 5a 74 14 8d 85 90 01 04 50 ff 15 90 01 04 33 c0 5f 5e 5b c9 c3 8d 45 a4 50 8d 45 b4 50 53 53 53 53 53 8d 85 90 01 04 53 50 53 ff 15 90 00 } //100
	condition:
		((#a_03_0  & 1)*100) >=100
 
}