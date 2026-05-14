
rule Trojan_Win64_BrowserStealer_PVA_MTB{
	meta:
		description = "Trojan:Win64/BrowserStealer.PVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {2b f8 49 8d 55 0f 44 89 74 24 48 48 8d 4d f4 48 89 4c 24 40 89 7c 24 38 48 89 44 24 30 44 89 74 24 28 4c 89 74 24 20 4c 8d 4d 80 44 8b c6 48 8b 4d e8 ff 15 } //3
		$a_00_1 = {4c 00 6f 00 63 00 61 00 6c 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 32 00 5f 00 53 00 69 00 6e 00 67 00 6c 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 } //4 Local\Project2_SingleInstance
		$a_00_2 = {62 75 69 6c 64 5f 7a 69 70 5f 70 61 79 6c 6f 61 64 3a 20 66 61 69 6c 65 64 20 74 6f 20 61 70 70 65 6e 64 20 6c 6f 67 73 2e 74 78 74 } //1 build_zip_payload: failed to append logs.txt
		$a_00_3 = {73 65 6e 64 5f 61 72 63 68 69 76 65 3a 20 66 61 69 6c 65 64 20 74 6f 20 74 72 61 6e 73 6d 69 74 20 7a 69 70 20 70 61 79 6c 6f 61 64 } //1 send_archive: failed to transmit zip payload
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*4+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=9
 
}