
rule TrojanSpy_Win32_Banker_VH{
	meta:
		description = "TrojanSpy:Win32/Banker.VH,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 69 6e 61 6e 7a 70 6f 72 74 61 6c 2e 66 69 64 75 63 69 61 2e 64 65 } //01 00  finanzportal.fiducia.de
		$a_01_1 = {69 6e 74 65 72 6e 65 74 73 75 62 65 2e 61 6b 62 61 6e 6b 2e 63 6f 6d 2e 74 72 } //01 00  internetsube.akbank.com.tr
		$a_01_2 = {62 61 6e 6b 6f 66 61 6d 65 72 69 63 61 } //01 00  bankofamerica
		$a_01_3 = {43 4c 49 43 4b 53 3d 25 73 } //01 00  CLICKS=%s
		$a_01_4 = {79 61 70 69 6b 72 65 64 69 2e 63 6f 6d 2e 74 72 } //01 00  yapikredi.com.tr
		$a_01_5 = {25 73 3d 4b 45 59 4c 4f 47 47 45 44 3a 25 73 20 4b 45 59 53 52 45 41 44 3a 25 73 } //01 00  %s=KEYLOGGED:%s KEYSREAD:%s
		$a_01_6 = {70 61 73 73 77 6f 72 64 } //01 00  password
		$a_01_7 = {49 45 20 41 75 74 6f 20 43 6f 6d 70 6c 65 74 65 20 46 69 65 6c 64 73 } //01 00  IE Auto Complete Fields
		$a_01_8 = {49 45 3a 50 61 73 73 77 6f 72 64 2d 50 72 6f 74 65 63 74 65 64 20 73 69 74 65 73 } //01 00  IE:Password-Protected sites
		$a_01_9 = {44 65 6c 65 74 65 64 20 4f 45 20 41 63 63 6f 75 6e 74 } //01 00  Deleted OE Account
		$a_01_10 = {2f 75 70 6c 6f 61 64 2e 70 68 70 } //01 00  /upload.php
		$a_01_11 = {2f 6d 61 69 6c 2e 70 68 70 } //00 00  /mail.php
	condition:
		any of ($a_*)
 
}