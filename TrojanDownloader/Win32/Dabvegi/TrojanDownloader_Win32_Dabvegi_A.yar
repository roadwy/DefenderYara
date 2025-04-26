
rule TrojanDownloader_Win32_Dabvegi_A{
	meta:
		description = "TrojanDownloader:Win32/Dabvegi.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 61 64 44 6f 77 6e 6c 6f 61 64 65 72 00 } //1
		$a_01_1 = {43 68 61 6d 61 46 69 72 65 77 61 6c 6c 00 } //1 桃浡䙡物睥污l
		$a_01_2 = {43 72 54 78 74 00 } //1 牃硔t
		$a_01_3 = {4d 79 73 66 78 00 } //1 祍晳x
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}