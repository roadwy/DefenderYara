
rule TrojanSpy_Win32_Bancos_AKJ{
	meta:
		description = "TrojanSpy:Win32/Bancos.AKJ,SIGNATURE_TYPE_PEHSTR_EXT,35 00 35 00 0b 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 74 61 2e 6a 70 67 } //10 Conta.jpg
		$a_01_1 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 6c 6c 20 55 73 65 72 73 5c 4d 65 6e 75 20 49 6e 69 63 69 61 72 5c 50 72 6f 67 72 61 6d 61 73 5c 49 6e 69 63 69 61 6c 69 7a 61 72 5c } //10 C:\Documents and Settings\All Users\Menu Iniciar\Programas\Inicializar\
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 6e 65 74 62 61 6e 6b 69 6e 67 32 2e 62 61 6e 65 73 70 61 2e 63 6f 6d 2e 62 72 20 2d 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //10 https://netbanking2.banespa.com.br - Internet Explorer
		$a_01_3 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 \Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {40 75 6f 6c 2e 63 6f 6d 2e 62 72 } //10 @uol.com.br
		$a_01_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 79 73 65 6c 66 73 75 73 70 69 63 69 6f 75 73 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d 2e 62 72 21 } //1 http://www.myselfsuspicious@hotmail.com.br!
		$a_01_6 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 73 61 6e 74 61 6e 64 65 72 6e 65 74 2e 63 6f 6d 2e 62 72 2f 64 65 66 61 75 6c 74 2e 61 73 70 3f 74 78 74 41 67 65 6e 63 69 61 3d } //1 https://www.santandernet.com.br/default.asp?txtAgencia=
		$a_01_7 = {42 61 6e 63 6f 20 42 72 61 64 65 73 63 6f 20 53 2f 41 } //1 Banco Bradesco S/A
		$a_01_8 = {6c 74 69 70 6c 6f 20 7c 20 4c 6f 67 69 6e 20 4d 65 75 20 48 53 42 43 } //1 ltiplo | Login Meu HSBC
		$a_01_9 = {46 34 36 34 45 32 37 34 46 42 32 45 34 33 45 46 31 32 34 46 35 43 44 41 30 42 35 35 46 38 33 35 45 38 33 43 32 43 37 44 46 35 31 36 44 37 30 46 34 38 35 46 45 32 39 30 42 46 36 43 38 44 42 31 32 38 44 44 42 43 37 36 44 37 37 31 42 37 34 38 46 43 32 38 30 34 36 31 38 37 42 33 39 45 41 42 43 41 34 43 42 42 } //1 F464E274FB2E43EF124F5CDA0B55F835E83C2C7DF516D70F485FE290BF6C8DB128DDBC76D771B748FC28046187B39EABCA4CBB
		$a_01_10 = {37 46 42 45 36 36 38 42 42 37 31 39 36 30 43 34 42 46 30 35 34 46 38 32 46 36 35 33 38 34 41 35 35 33 38 31 41 41 33 45 45 39 31 44 44 38 30 41 34 38 34 31 45 41 31 37 43 37 41 44 34 38 46 36 31 30 33 45 45 32 30 36 32 36 43 45 36 43 42 37 41 38 34 39 46 30 35 31 44 31 30 39 43 43 30 43 37 39 41 31 33 33 46 37 30 31 33 33 43 33 33 38 } //1 7FBE668BB71960C4BF054F82F65384A55381AA3EE91DD80A4841EA17C7AD48F6103EE20626CE6CB7A849F051D109CC0C79A133F70133C338
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=53
 
}