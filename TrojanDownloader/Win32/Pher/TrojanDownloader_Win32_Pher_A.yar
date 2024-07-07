
rule TrojanDownloader_Win32_Pher_A{
	meta:
		description = "TrojanDownloader:Win32/Pher.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 73 00 63 00 20 00 6f 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 20 00 2f 00 74 00 6e 00 20 00 22 00 3a 00 73 00 63 00 68 00 6e 00 61 00 6d 00 65 00 22 00 20 00 2f 00 74 00 72 00 20 00 22 00 5c 00 22 00 3a 00 70 00 61 00 74 00 68 00 22 00 5c 00 22 00 20 00 20 00 3a 00 76 00 69 00 73 00 74 00 61 00 } //2 schtasks /create /sc onlogon /tn ":schname" /tr "\":path"\"  :vista
		$a_01_1 = {74 79 70 65 5f 66 75 6e 63 74 69 6f 6e 5f 64 65 43 72 79 70 74 } //3 type_function_deCrypt
		$a_01_2 = {64 77 69 6e 73 74 61 6c 6c 52 65 67 73 65 74 74 69 6e 67 } //2 dwinstallRegsetting
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=7
 
}