
rule Ransom_Win32_Yoyorypt_A{
	meta:
		description = "Ransom:Win32/Yoyorypt.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 6e 20 35 20 2d 77 20 33 30 30 30 20 3e 20 4e 75 6c 20 26 20 44 65 6c 20 22 25 73 22 } //01 00  cmd.exe /C ping 1.1.1.1 -n 5 -w 3000 > Nul & Del "%s"
		$a_01_1 = {72 65 61 64 5f 74 6f 5f 74 78 74 5f 66 69 6c 65 2e 79 79 74 6f } //01 00  read_to_txt_file.yyto
		$a_01_2 = {68 65 6c 70 5f 74 6f 5f 64 65 63 72 79 70 74 2e 74 78 74 } //00 00  help_to_decrypt.txt
		$a_01_3 = {00 7e } //15 00  縀
	condition:
		any of ($a_*)
 
}