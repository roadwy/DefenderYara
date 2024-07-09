
rule Trojan_BAT_SpySnake_MAQ_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_03_0 = {11 04 16 09 1f 0f 1f 10 28 ?? ?? ?? 0a 06 09 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 13 05 02 28 ?? ?? ?? 0a 13 06 28 ?? ?? ?? 0a 11 05 11 06 16 11 06 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c dd 06 00 00 00 26 dd 00 00 00 00 08 2a } //10
		$a_01_1 = {48 61 6e 64 6c 65 49 6e 63 6f 6d 69 6e 67 43 6f 6e 6e 65 63 74 69 6f 6e 73 } //1 HandleIncomingConnections
		$a_01_2 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 20 00 74 00 68 00 65 00 20 00 73 00 65 00 72 00 76 00 65 00 72 00 } //1 shutdown the server
		$a_01_3 = {49 41 73 79 6e 63 4c 6f 63 61 6c } //1 IAsyncLocal
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}