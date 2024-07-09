
rule TrojanDownloader_Win32_Lacrec_A{
	meta:
		description = "TrojanDownloader:Win32/Lacrec.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {43 eb 8b 80 3d ?? ?? ?? ?? 01 75 4c 68 ?? ?? ?? ?? e8 } //2
		$a_03_1 = {80 7c 18 ff 3b 75 45 8d 04 b5 ?? ?? ?? ?? 50 8b cb 49 ba 01 00 00 00 } //2
		$a_01_2 = {43 4f 43 4c 41 00 } //1 佃䱃A
		$a_01_3 = {52 65 67 43 6f 6d 33 32 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}