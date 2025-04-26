
rule TrojanSpy_Win32_Bancos_KS{
	meta:
		description = "TrojanSpy:Win32/Bancos.KS,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0d 00 09 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 62 79 31 33 37 77 2e 62 61 79 31 33 37 2e 6d 61 69 6c 2e 6c 69 76 65 2e 63 6f 6d 2f 6d 61 69 6c 2f 48 69 70 4c 69 67 68 74 2e 61 73 70 78 3f 6e 3d } //1 http://by137w.bay137.mail.live.com/mail/HipLight.aspx?n=
		$a_00_1 = {68 74 74 70 3a 2f 2f 62 6c 31 30 33 77 2e 62 6c 75 31 30 33 2e 6d 61 69 6c 2e 6c 69 76 65 2e 63 6f 6d 2f 6d 61 69 6c 2f 49 6e 62 6f 78 4c 69 67 68 74 2e 61 73 70 78 3f 6e 3d } //1 http://bl103w.blu103.mail.live.com/mail/InboxLight.aspx?n=
		$a_00_2 = {68 74 74 70 3a 2f 2f 62 79 31 34 32 77 2e 62 61 79 31 34 32 2e 6d 61 69 6c 2e 6c 69 76 65 2e 63 6f 6d 2f 6d 61 69 6c 2f 49 6e 62 6f 78 4c 69 67 68 74 2e 61 73 70 78 3f 6e 3d } //1 http://by142w.bay142.mail.live.com/mail/InboxLight.aspx?n=
		$a_00_3 = {68 74 74 70 3a 2f 2f 62 79 31 33 37 77 2e 62 61 79 31 33 37 2e 6d 61 69 6c 2e 6c 69 76 65 2e 63 6f 6d 2f 6d 61 69 6c 2f 49 6e 62 6f 78 4c 69 67 68 74 2e 61 73 70 78 3f } //1 http://by137w.bay137.mail.live.com/mail/InboxLight.aspx?
		$a_00_4 = {2e 6d 61 69 6c 2e 6c 69 76 65 2e 63 6f 6d 2f 6d 61 69 6c 2f 53 65 6e 64 4d 65 73 73 61 67 65 4c 69 67 68 74 2e 61 73 70 78 3f 5f 65 63 3d 31 26 6e 3d } //1 .mail.live.com/mail/SendMessageLight.aspx?_ec=1&n=
		$a_00_5 = {63 6f 6d 65 72 63 69 6f 64 6f 6f 75 72 6f 40 67 6d 61 69 6c 2e 63 6f 6d } //1 comerciodoouro@gmail.com
		$a_00_6 = {4f 6c 61 2c 20 6e 61 6f 20 64 65 69 78 65 20 64 65 20 6f 6c 68 61 72 20 6d 69 6e 68 61 20 6d 65 6e 73 61 67 65 6d } //1 Ola, nao deixe de olhar minha mensagem
		$a_00_7 = {45 6d 61 69 6c 20 41 20 65 6e 76 69 61 72 } //1 Email A enviar
		$a_01_8 = {e8 88 2f fa ff 68 f0 38 46 00 33 c9 ba 8c 01 00 00 8b 83 00 03 00 00 e8 ad 79 fd ff 40 0f 8f be 00 00 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*10) >=13
 
}