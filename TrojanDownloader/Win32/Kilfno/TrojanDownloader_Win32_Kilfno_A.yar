
rule TrojanDownloader_Win32_Kilfno_A{
	meta:
		description = "TrojanDownloader:Win32/Kilfno.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 63 20 64 65 6c 65 74 65 20 52 61 76 54 61 73 6b 00 } //1
		$a_01_1 = {8a 44 32 01 8a 0c 32 04 06 80 e9 08 24 0f 8b fe c0 e1 04 02 c1 } //1
		$a_01_2 = {74 4d 6a 00 6a 00 6a 10 } //1 䵴jjၪ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}