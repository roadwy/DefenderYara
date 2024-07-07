
rule TrojanSpy_Win32_Banker_HP{
	meta:
		description = "TrojanSpy:Win32/Banker.HP,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {43 61 70 74 75 72 61 6e 64 6f 20 63 6f 6e 74 61 74 6f 73 20 64 61 20 70 61 67 69 6e 61 } //1 Capturando contatos da pagina
		$a_00_1 = {77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 61 63 63 6f 75 6e 74 73 2f 73 65 72 76 69 63 65 6c 6f 67 69 6e 3f 73 65 72 76 69 63 65 3d 6f 72 6b 75 74 } //1 www.google.com/accounts/servicelogin?service=orkut
		$a_00_2 = {65 6d 61 69 6c } //1 email
		$a_00_3 = {70 61 73 73 77 64 } //1 passwd
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 49 43 52 4f 53 4f 46 54 5c 57 49 4e 44 4f 57 53 5c 43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e } //1 SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN
		$a_00_5 = {69 65 78 70 6c 6f 72 65 72 73 6b 75 74 } //1 iexplorerskut
		$a_00_6 = {53 59 53 54 45 4d 41 20 44 45 20 53 43 52 41 50 54 20 44 4c 4c 48 4f 53 54 43 } //1 SYSTEMA DE SCRAPT DLLHOSTC
		$a_02_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6f 72 6b 75 74 2e 63 6f 6d 90 03 14 10 2e 62 72 2f 66 72 69 65 6e 64 73 4c 69 73 74 2e 61 73 70 78 2f 73 63 72 61 70 62 6f 6f 6b 2e 61 73 70 78 3f 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_02_7  & 1)*1) >=8
 
}