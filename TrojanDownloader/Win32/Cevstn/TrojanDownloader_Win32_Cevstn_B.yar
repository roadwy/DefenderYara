
rule TrojanDownloader_Win32_Cevstn_B{
	meta:
		description = "TrojanDownloader:Win32/Cevstn.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e 21 53 8b 44 24 08 8d 0c 02 8a 04 02 2a c2 8a d8 c0 eb 04 c0 e0 04 02 d8 42 3b 54 24 0c 88 19 7c e1 } //1
		$a_03_1 = {74 31 88 18 8d 85 90 01 02 ff ff 6a 5c 50 ff 15 90 01 02 40 00 59 3b c3 59 74 1a 80 78 ff 3a 75 05 88 58 01 eb 02 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}