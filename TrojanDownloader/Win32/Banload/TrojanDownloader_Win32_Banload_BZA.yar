
rule TrojanDownloader_Win32_Banload_BZA{
	meta:
		description = "TrojanDownloader:Win32/Banload.BZA,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 4c 4c 3a 21 41 44 48 3a 52 43 34 2b 52 53 41 3a 2b 48 49 47 48 3a 2b 4d 45 44 49 55 4d 3a 2b 4c 4f 57 3a 2b 53 53 4c 76 32 3a 2b 45 58 50 } //1 ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP
		$a_01_1 = {49 45 28 41 4c 28 22 25 73 22 2c 34 29 2c 22 41 4c 28 5c 22 25 30 3a 73 5c 22 2c 33 29 22 2c 22 4a 4b 28 5c 22 25 31 3a 73 5c 22 2c 5c 22 25 30 3a 73 5c 22 29 22 29 } //1 IE(AL("%s",4),"AL(\"%0:s\",3)","JK(\"%1:s\",\"%0:s\")")
		$a_00_2 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73 } //1
		$a_01_3 = {74 6f 70 6f 3d 50 48 49 53 48 49 4e 47 20 63 78 32 3a } //1 topo=PHISHING cx2:
		$a_01_4 = {2e 63 6f 6d 2e 62 72 2f } //1 .com.br/
		$a_03_5 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}