
rule PWS_Win32_Hawthief_A{
	meta:
		description = "PWS:Win32/Hawthief.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 10 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //01 00  Internet Explorer_Server
		$a_01_1 = {45 6d 62 65 64 64 65 64 57 42 20 68 74 74 70 3a 2f 2f 62 73 61 6c 73 61 2e } //01 00  EmbeddedWB http://bsalsa.
		$a_01_2 = {6d 65 6e 73 61 67 65 6d 28 6e 73 29 } //01 00  mensagem(ns)
		$a_00_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 62 00 79 00 31 00 33 00 37 00 77 00 2e 00 62 00 61 00 79 00 31 00 33 00 37 00 2e 00 6d 00 61 00 69 00 6c 00 2e 00 } //01 00  http://by137w.bay137.mail.
		$a_01_4 = {63 6f 6e 74 61 63 74 74 65 6d 70 2e 68 74 6d 6c } //01 00  contacttemp.html
		$a_01_5 = {64 4c 6f 67 69 6e 5f 4d 6f 64 65 5f 44 69 66 66 55 73 65 72 } //01 00  dLogin_Mode_DiffUser
		$a_01_6 = {54 65 6e 74 65 20 6e 6f 76 61 6d 65 6e 74 65 2e } //01 00  Tente novamente.
		$a_01_7 = {2f 63 67 69 2d 62 69 6e 2f 63 6f 6d 70 6f 73 65 3f } //01 00  /cgi-bin/compose?
		$a_01_8 = {4d 53 4e 4c 4f 47 4f 46 46 } //01 00  MSNLOGOFF
		$a_01_9 = {53 65 6c 65 63 74 41 6c 6c 4d 65 73 73 61 67 65 73 } //01 00  SelectAllMessages
		$a_01_10 = {63 6f 6e 74 61 63 74 73 2e 68 74 6d 6c } //01 00  contacts.html
		$a_01_11 = {2e 61 73 70 78 3f 46 6f 6c 64 65 72 49 44 3d 30 30 30 30 30 30 30 30 } //01 00  .aspx?FolderID=00000000
		$a_01_12 = {74 65 72 72 61 2e 63 6f 6d 2e 62 72 } //01 00  terra.com.br
		$a_01_13 = {50 65 67 61 6e 64 6f 20 6f 73 20 75 73 75 } //01 00  Pegando os usu
		$a_01_14 = {44 65 73 63 6f 6e 65 63 74 61 6e 64 6f 20 64 6f 20 68 6f 74 6d 61 69 6c } //01 00  Desconectando do hotmail
		$a_01_15 = {70 61 73 73 77 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}