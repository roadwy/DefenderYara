
rule Trojan_Win64_NetLoader_MK_MTB{
	meta:
		description = "Trojan:Win64/NetLoader.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 06 00 00 "
		
	strings :
		$a_01_0 = {c7 45 20 68 00 00 00 0f 57 c0 0f 11 45 28 0f 11 45 38 0f 11 45 48 0f 11 45 58 0f 11 45 68 0f 11 45 78 48 8b 4b 10 48 b8 ff ff ff ff ff ff ff 7f 48 2b c1 48 83 f8 01 } //25
		$a_01_1 = {50 69 6e 67 43 6c 69 65 6e 74 2f 31 2e 30 } //4 PingClient/1.0
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 65 64 5f 66 69 6c 65 5f } //3 downloaded_file_
		$a_01_3 = {41 55 54 48 5f 53 55 43 43 45 53 53 } //1 AUTH_SUCCESS
		$a_01_4 = {66 69 6c 65 5f 75 72 6c } //1 file_url
		$a_01_5 = {43 3a 5c 49 6e 66 6f } //1 C:\Info
	condition:
		((#a_01_0  & 1)*25+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=35
 
}