
rule Trojan_Win64_KeyLogger_NK_MTB{
	meta:
		description = "Trojan:Win64/KeyLogger.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 01 d0 4c 89 f2 4c 89 45 ?? 41 b8 02 00 00 00 e8 21 fc ff ff e9 e0 fe ff ff 48 8d 0d 3d e8 0a 00 48 c7 45 ?? 00 00 00 00 e8 98 fb ff ff } //3
		$a_03_1 = {48 8b 10 48 8d 4c 24 ?? 4c 8d 4c 24 ?? 41 b8 10 00 00 00 e8 2b 8f ff ff 85 c0 7e 17 0f b7 4c 24 ?? 66 89 4b 18 89 43 14 eb ab } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}
rule Trojan_Win64_KeyLogger_NK_MTB_2{
	meta:
		description = "Trojan:Win64/KeyLogger.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 20 41 74 61 70 69 20 78 38 36 5f 36 34 20 44 72 69 76 65 72 } //2 Windows Atapi x86_64 Driver
		$a_01_1 = {68 00 61 00 63 00 6b 00 73 00 2e 00 74 00 78 00 74 00 } //2 hacks.txt
		$a_01_2 = {43 68 61 76 65 20 61 62 65 72 74 61 20 63 6f 6d 20 73 75 63 65 73 73 6f } //1 Chave aberta com sucesso
		$a_01_3 = {45 72 72 6f 20 61 6f 20 6f 62 74 65 72 20 6f 20 6e 6f 6d 65 20 64 6f 20 75 73 75 } //1 Erro ao obter o nome do usu
		$a_01_4 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 57 } //1 InternetConnectW
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}