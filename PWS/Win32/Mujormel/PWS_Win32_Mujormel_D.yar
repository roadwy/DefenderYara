
rule PWS_Win32_Mujormel_D{
	meta:
		description = "PWS:Win32/Mujormel.D,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {68 00 64 00 76 00 65 00 72 00 61 00 32 00 30 00 31 00 33 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //4 hdvera2013@gmail.com
		$a_01_1 = {6e 00 6f 00 74 00 69 00 66 00 69 00 63 00 61 00 63 00 61 00 6f 00 32 00 30 00 31 00 33 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //4 notificacao2013@gmail.com
		$a_01_2 = {77 00 65 00 62 00 63 00 74 00 40 00 75 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //2 webct@uol.com.br
		$a_01_3 = {71 00 77 00 31 00 30 00 32 00 30 00 33 00 30 00 } //2 qw102030
		$a_01_4 = {31 00 6e 00 74 00 33 00 72 00 6e 00 33 00 74 00 2e 00 2e 00 2e 00 2e 00 2e 00 3a 00 } //2 1nt3rn3t.....:
		$a_01_5 = {33 00 6e 00 74 00 72 00 30 00 6e 00 31 00 63 00 34 00 2e 00 2e 00 2e 00 2e 00 3a 00 } //2 3ntr0n1c4....:
		$a_01_6 = {43 00 61 00 72 00 74 00 34 00 30 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 3a 00 } //2 Cart40.......:
		$a_01_7 = {46 00 6c 00 61 00 73 00 68 00 50 00 6c 00 61 00 79 00 65 00 72 00 55 00 70 00 64 00 61 00 74 00 65 00 } //1 FlashPlayerUpdate
		$a_01_8 = {73 00 65 00 6e 00 64 00 65 00 72 00 65 00 64 00 65 00 6d 00 61 00 69 00 6c 00 2e 00 74 00 6d 00 70 00 } //1 senderedemail.tmp
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}