
rule TrojanDownloader_Win32_Iokidoki_A{
	meta:
		description = "TrojanDownloader:Win32/Iokidoki.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 6b 73 74 61 74 69 6f 6e 20 34 2e 30 00 00 00 00 ff ff ff ff 0d 00 00 00 20 48 6f 6d 65 20 45 64 69 74 69 6f 6e 00 00 00 ff ff ff ff 0d 00 00 00 20 50 72 6f 66 65 73 73 69 6f 6e 61 6c 00 00 00 ff ff ff ff 13 00 00 00 20 44 61 74 61 63 65 6e 74 65 72 20 45 64 69 74 69 6f 6e } //1
		$a_01_1 = {5c 48 6f 74 66 69 78 5c 5c 51 32 34 36 30 30 39 00 00 00 00 ff ff ff ff 0f 00 00 00 53 65 72 76 69 63 65 20 50 61 63 6b 20 36 61 00 ff ff ff ff 0d 00 00 00 53 65 72 76 69 63 65 20 50 61 63 6b } //1
		$a_01_2 = {eb c8 8b 45 fc 5e 5b 8b e5 5d c2 0c 00 00 75 00 72 00 6c 00 00 00 70 00 69 00 64 00 00 00 ff ff ff ff 05 00 00 00 76 69 73 74 61 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}