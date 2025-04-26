
rule TrojanDownloader_Win32_Adload_DW_bit{
	meta:
		description = "TrojanDownloader:Win32/Adload.DW!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2d 77 65 73 74 2d 32 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f [0-50] 2f 4d 65 7a 72 69 67 69 2e 65 78 65 } //1
		$a_01_1 = {00 2e 63 6f 6e 66 69 67 } //1 ⸀潣普杩
		$a_01_2 = {7b 74 6d 70 7d 5c 4d 65 7a 72 69 67 69 2e 65 78 65 } //1 {tmp}\Mezrigi.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}