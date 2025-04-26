
rule Trojan_Win32_Dialsnif_gen_A{
	meta:
		description = "Trojan:Win32/Dialsnif.gen!A,SIGNATURE_TYPE_PEHSTR,14 00 0f 00 0a 00 00 "
		
	strings :
		$a_01_0 = {31 db b8 6f 00 00 00 30 44 1d 00 80 7c 1d 00 09 74 0e 05 93 00 00 00 43 81 fb 00 10 00 00 7c e7 89 fb 81 c3 00 04 00 00 } //3
		$a_01_1 = {85 c0 74 0e c6 00 00 48 80 38 20 74 05 c6 00 00 eb f5 8b 44 24 04 6a 00 50 56 e8 } //3
		$a_01_2 = {55 8b 6c 24 10 8b 5c 24 0c 8b 54 24 08 43 8a 44 1d 00 84 c0 74 06 88 02 42 43 eb f2 43 88 02 89 d8 5d c2 0c 00 } //3
		$a_01_3 = {56 8b 74 24 08 31 db 31 c0 b9 10 00 00 00 8a 1e 46 80 eb 30 72 0b 80 fb 09 77 06 f7 e1 01 d8 eb ed 5e c2 04 00 } //3
		$a_01_4 = {8b 4d fc 8b 5d 08 81 c3 3c 02 00 00 b8 9c 01 00 00 89 03 01 c3 e2 fa 8b 5d 08 81 c3 3c 02 00 00 } //3
		$a_01_5 = {6a 61 76 61 73 63 72 69 70 74 3a 27 3c 68 74 6d 6c 3e 3c 68 65 61 64 3e 3c 74 69 74 6c 65 3e 4d 65 6d 62 65 72 73 20 41 72 65 61 20 41 63 63 65 73 73 3c 2f 74 69 74 6c 65 3e 3c 2f 68 65 61 64 3e 3c 62 6f 64 79 3e 3c 62 69 67 3e 3c 63 65 6e 74 65 72 3e 3c 62 72 3e 3c 62 72 3e 53 61 76 65 20 74 68 65 20 6c 6f 67 69 6e 20 61 6e 64 20 70 61 73 73 77 6f 72 64 20 67 65 6e 65 72 61 74 65 64 20 66 6f 72 20 79 6f 75 2e 20 49 74 20 77 69 6c 6c 20 67 72 61 6e 74 20 61 63 63 65 73 73 20 66 6f 72 20 37 20 64 61 79 73 2e 3c 62 72 3e 3c 62 72 3e 59 6f 75 72 20 4c 4f 47 49 4e 20 69 73 3a 20 3c 62 3e } //1 javascript:'<html><head><title>Members Area Access</title></head><body><big><center><br><br>Save the login and password generated for you. It will grant access for 7 days.<br><br>Your LOGIN is: <b>
		$a_01_6 = {3c 2f 62 3e 3c 62 72 3e 59 6f 75 72 20 50 41 53 53 57 4f 52 44 20 69 73 3a 20 3c 62 3e } //1 </b><br>Your PASSWORD is: <b>
		$a_01_7 = {3c 2f 62 3e 3c 62 72 3e 4d 65 6d 62 65 72 73 20 41 72 65 61 20 55 52 4c 3a 20 3c 61 20 68 72 65 66 3d } //1 </b><br>Members Area URL: <a href=
		$a_01_8 = {3c 2f 61 3e 3c 62 72 3e 3c 62 72 3e 54 6f 20 61 63 63 65 73 73 20 75 73 65 20 79 6f 75 72 20 75 73 75 61 6c 20 63 6f 6e 6e 65 63 74 69 6f 6e 2e 3c 2f 63 65 6e 74 65 72 3e 3c 2f 62 69 67 3e 3c 2f 62 6f 64 79 3e 3c 2f 68 74 6d 6c 3e 27 } //1 </a><br><br>To access use your usual connection.</center></big></body></html>'
		$a_01_9 = {41 54 4d 30 } //1 ATM0
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=15
 
}