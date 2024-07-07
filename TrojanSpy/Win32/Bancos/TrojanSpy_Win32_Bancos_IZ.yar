
rule TrojanSpy_Win32_Bancos_IZ{
	meta:
		description = "TrojanSpy:Win32/Bancos.IZ,SIGNATURE_TYPE_PEHSTR,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 61 6c 6a 61 7a 69 72 61 68 66 6f 72 64 2e 63 6f 6d 2f 68 65 6c 70 64 65 73 6b 2f 75 70 6c 6f 61 64 2f 64 69 72 2f 62 2e 70 68 70 3f 63 68 61 76 65 3d } //1 http://aljazirahford.com/helpdesk/upload/dir/b.php?chave=
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 65 66 36 67 00 ff ff ff ff 10 00 00 00 75 65 72 72 65 69 72 6f 73 2e 63 6f 6d 2f 65 66 } //1
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 69 6e 74 65 72 6e 65 74 62 00 00 00 ff ff ff ff 0a 00 00 00 61 6e 6b 69 6e 67 2e 63 61 69 00 00 ff ff ff ff 0e 00 00 00 78 61 2e 67 6f 76 2e 62 72 2f 53 49 49 42 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}