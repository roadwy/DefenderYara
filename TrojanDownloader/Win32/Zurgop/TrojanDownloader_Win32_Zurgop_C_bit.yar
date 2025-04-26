
rule TrojanDownloader_Win32_Zurgop_C_bit{
	meta:
		description = "TrojanDownloader:Win32/Zurgop.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 6c 6f 63 61 6c 4e 45 54 53 65 72 76 69 63 65 } //1 Software\localNETService
		$a_01_1 = {8a 4c 35 d4 32 0c 02 32 ca 46 83 fe 10 88 0c 02 75 02 33 f6 42 3b d3 72 e7 } //1
		$a_03_2 = {69 72 73 2e c7 81 ?? ?? ?? ?? 69 72 77 2e c7 81 ?? ?? ?? ?? 31 61 66 69 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}