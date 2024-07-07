
rule Worm_Win32_Barten_A{
	meta:
		description = "Worm:Win32/Barten.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 6d 74 70 2e 74 65 72 72 61 2e 63 6f 6d 2e 62 72 3b 76 61 63 } //1 smtp.terra.com.br;vac
		$a_01_1 = {73 6d 74 70 2e 74 65 72 72 61 2e 63 6f 6d 2e 62 72 3b 62 61 72 61 74 61 } //1 smtp.terra.com.br;barata
		$a_01_2 = {63 6f 6e 73 65 6e 73 75 61 6c 2e 25 } //1 consensual.%
		$a_01_3 = {6c 73 74 72 65 70 65 74 69 64 6f 73 } //1 lstrepetidos
		$a_01_4 = {3c 74 69 74 6c 65 3e 4d 65 6e 69 6e 61 } //1 <title>Menina
		$a_01_5 = {5f 5f 7a 62 53 65 73 73 69 6f 6e 54 4d 50 2f 76 69 64 65 6f 2e 70 68 70 } //1 __zbSessionTMP/video.php
		$a_01_6 = {4d 65 73 73 65 6e 67 65 72 5c 6d 73 6d 73 67 73 2e 65 78 65 } //1 Messenger\msmsgs.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}