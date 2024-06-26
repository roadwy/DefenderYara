
rule PWS_Win32_Yatkutur_B{
	meta:
		description = "PWS:Win32/Yatkutur.B,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0a 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 00 65 00 63 00 6c 00 61 00 64 00 6f 00 20 00 76 00 69 00 72 00 74 00 75 00 61 00 6c 00 2e 00 } //02 00  teclado virtual.
		$a_01_1 = {43 61 64 61 73 74 72 6f } //02 00  Cadastro
		$a_00_2 = {65 64 74 73 65 6e 68 61 } //02 00  edtsenha
		$a_00_3 = {42 00 72 00 61 00 73 00 69 00 6c 00 } //02 00  Brasil
		$a_80_4 = {62 61 6e 6b 69 6e 67 } //banking  02 00 
		$a_00_5 = {73 00 61 00 6e 00 74 00 61 00 6e 00 64 00 65 00 72 00 } //01 00  santander
		$a_00_6 = {41 70 70 48 6f 6f 6b } //01 00  AppHook
		$a_00_7 = {4d 6f 75 73 65 48 6f 6f 6b } //01 00  MouseHook
		$a_00_8 = {61 72 71 75 69 76 6f } //01 00  arquivo
		$a_00_9 = {70 72 69 76 61 63 } //00 00  privac
	condition:
		any of ($a_*)
 
}