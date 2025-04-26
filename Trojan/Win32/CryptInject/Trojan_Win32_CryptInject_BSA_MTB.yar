
rule Trojan_Win32_CryptInject_BSA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {6e 66 68 67 62 64 78 73 76 61 67 6c 61 78 64 6d 68 65 6b 65 63 61 78 61 68 64 66 78 71 71 64 76 67 6b 63 77 77 70 65 6b 74 6e 79 6f 76 6d 6e 6a 6f 6b 62 78 77 78 63 70 70 74 78 70 71 62 63 77 62 72 6f 63 68 76 76 6d 71 75 65 66 6c 67 6f 65 76 76 77 73 78 73 63 72 } //10 nfhgbdxsvaglaxdmhekecaxahdfxqqdvgkcwwpektnyovmnjokbxwxcpptxpqbcwbrochvvmqueflgoevvwsxscr
		$a_01_1 = {78 68 78 6f 6e 66 63 61 72 70 70 6b 61 72 75 79 77 67 6d 76 6a 71 65 76 6d 66 78 73 79 79 6b 62 65 61 76 72 79 73 75 78 6b 69 6c 75 76 71 6b 71 76 77 6a 67 79 73 64 66 6f 72 71 67 6b 6d 6d 75 6b 76 6a 72 70 65 69 72 6e 67 6f 78 72 6f 74 73 73 63 67 77 6f 63 6f 79 78 65 } //5 xhxonfcarppkaruywgmvjqevmfxsyykbeavrysuxkiluvqkqvwjgysdforqgkmmukvjrpeirngoxrotsscgwocoyxe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=10
 
}