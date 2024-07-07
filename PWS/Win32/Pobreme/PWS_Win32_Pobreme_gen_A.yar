
rule PWS_Win32_Pobreme_gen_A{
	meta:
		description = "PWS:Win32/Pobreme.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {7a 75 6d 62 69 2e 70 68 70 3f 75 73 75 61 72 69 6f 3d } //1 zumbi.php?usuario=
		$a_01_1 = {6d 73 6e 2e 70 68 70 3f 75 73 75 61 72 69 6f 3d } //1 msn.php?usuario=
		$a_01_2 = {65 64 74 5f 73 65 6e 68 61 } //1 edt_senha
		$a_01_3 = {26 26 73 65 6e 68 61 3d } //1 &&senha=
		$a_01_4 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 6d 73 6e 6d 73 67 72 2e 65 78 65 20 6d 73 6e 6d 73 67 72 } //1 netsh firewall add allowedprogram c:\windows\msnmsgr.exe msnmsgr
		$a_01_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 6d 73 6e 6d 73 67 72 2e 65 78 65 } //1 taskkill /F /IM msnmsgr.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}