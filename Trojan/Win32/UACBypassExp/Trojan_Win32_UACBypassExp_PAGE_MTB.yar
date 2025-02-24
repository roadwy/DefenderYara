
rule Trojan_Win32_UACBypassExp_PAGE_MTB{
	meta:
		description = "Trojan:Win32/UACBypassExp.PAGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e1 } //2
		$a_01_1 = {47 65 6e 65 72 61 74 65 47 61 72 62 61 67 65 43 6f 64 65 } //1 GenerateGarbageCode
		$a_01_2 = {45 6e 63 72 79 70 74 44 65 63 72 79 70 74 58 4f 52 } //2 EncryptDecryptXOR
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=6
 
}