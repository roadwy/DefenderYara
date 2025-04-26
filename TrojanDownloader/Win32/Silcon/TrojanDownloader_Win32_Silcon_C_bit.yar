
rule TrojanDownloader_Win32_Silcon_C_bit{
	meta:
		description = "TrojanDownloader:Win32/Silcon.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {fe c2 02 1c 16 8a 04 16 8a 2c 1e 88 04 1e 88 2c 16 00 e8 47 8a 04 06 30 07 ff 4d 0c 75 e2 } //2
		$a_01_1 = {32 06 46 88 07 8b 5d f4 8b 4d f8 89 ca 83 e1 03 } //1
		$a_01_2 = {89 c3 8b 07 8b 4f 04 89 c7 89 c8 31 d2 f7 f6 97 f7 f6 29 d8 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}