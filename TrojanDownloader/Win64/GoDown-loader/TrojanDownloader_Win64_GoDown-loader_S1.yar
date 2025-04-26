
rule TrojanDownloader_Win64_GoDown-loader_S1{
	meta:
		description = "TrojanDownloader:Win64/GoDown-loader.S1,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 63 72 65 61 74 65 5f 6e 65 77 5f 66 69 6c 65 } //1 main.create_new_file
		$a_01_1 = {6d 61 69 6e 2e 77 72 69 74 65 5f 6e 65 77 5f 66 69 6c 65 } //1 main.write_new_file
		$a_01_2 = {6d 61 69 6e 2e 61 65 73 44 65 63 72 79 70 74 5f 6f 62 66 } //1 main.aesDecrypt_obf
		$a_01_3 = {6d 61 69 6e 2e 28 2a 45 78 65 63 29 2e 67 65 74 5f 63 6f 6d 6d 61 6e 64 5f 63 6f 6e 74 65 78 74 } //1 main.(*Exec).get_command_context
		$a_01_4 = {2f 6c 6f 61 64 65 72 2f 74 65 6d 70 2f 74 65 6d 70 2e 67 6f } //1 /loader/temp/temp.go
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}