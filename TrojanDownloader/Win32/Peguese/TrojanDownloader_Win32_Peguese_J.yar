
rule TrojanDownloader_Win32_Peguese_J{
	meta:
		description = "TrojanDownloader:Win32/Peguese.J,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00 } //5
		$a_01_1 = {06 74 6d 72 49 6e 69 fc 02 } //5
		$a_01_2 = {0c 74 6d 72 42 6c 6f 71 54 69 6d 65 72 12 } //5 琌牭求煯楔敭ቲ
		$a_01_3 = {0a 74 6d 72 46 32 54 69 6d 65 72 11 } //5 琊牭㉆楔敭ᅲ
		$a_01_4 = {0b 74 6d 72 45 73 63 54 69 6d 65 72 } //5 琋牭獅呣浩牥
		$a_03_5 = {8b 08 ff 51 1c 8b 85 90 01 02 ff ff 50 8d 95 90 01 02 ff ff b8 90 01 03 00 e8 90 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_03_5  & 1)*1) >=26
 
}