
rule Ransom_Win32_WannaCrypt_B_{
	meta:
		description = "Ransom:Win32/WannaCrypt.B!!WannaCrypt.gen!B,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {57 41 4e 4e 41 43 52 59 00 } //02 00 
		$a_00_1 = {21 57 61 6e 6e 61 44 65 63 72 79 70 74 6f 72 21 2e 65 78 65 } //01 00  !WannaDecryptor!.exe
		$a_00_2 = {75 2e 77 72 79 00 00 00 25 2e 31 66 20 42 54 43 } //01 00 
		$a_00_3 = {57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 3e 20 63 2e 76 62 73 } //00 00  WScript.CreateObject("WScript.Shell")> c.vbs
	condition:
		any of ($a_*)
 
}