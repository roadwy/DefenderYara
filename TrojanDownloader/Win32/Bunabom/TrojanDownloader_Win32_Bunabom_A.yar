
rule TrojanDownloader_Win32_Bunabom_A{
	meta:
		description = "TrojanDownloader:Win32/Bunabom.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 53 4f 46 54 57 41 52 45 5c 50 6c 61 79 4f 6e 6c 69 6e 65 55 53 5c } //1 \SOFTWARE\PlayOnlineUS\
		$a_01_1 = {2f 74 68 67 72 2e 61 73 70 3f 6d 61 63 3d 00 } //1
		$a_01_2 = {53 65 6e 64 20 4f 4b 21 00 } //1
		$a_03_3 = {64 ff 30 64 89 20 c6 45 fb 00 6a 00 6a 00 6a 00 6a 00 68 90 01 04 e8 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}