
rule Trojan_Win32_Eqtonex_SA_MTB{
	meta:
		description = "Trojan:Win32/Eqtonex.SA!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 45 4c 45 43 54 20 68 6f 73 74 6e 61 6d 65 2c 68 74 74 70 52 65 61 6c 6d 2c 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 2c 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 3b } //01 00  SELECT hostname,httpRealm,encryptedUsername,encryptedPassword FROM moz_logins;
		$a_01_1 = {54 6e 52 54 5a 58 52 4a 62 6d 5a 76 63 6d 31 68 64 47 6c 76 62 6c 42 79 62 32 4e 6c 63 33 4d } //01 00  TnRTZXRJbmZvcm1hdGlvblByb2Nlc3M
		$a_01_2 = {54 57 6c 6a 63 6d 39 7a 62 32 5a 30 58 48 42 6c 63 6e 4e 70 63 33 51 75 5a 47 46 30 } //01 00  TWljcm9zb2Z0XHBlcnNpc3QuZGF0
		$a_01_3 = {54 57 6c 6a 63 6d 39 7a 62 32 5a 30 58 46 4e 6c 59 58 4a 6a 61 46 77 } //01 00  TWljcm9zb2Z0XFNlYXJjaFw
		$a_01_4 = {56 30 56 53 4f 57 31 7a 62 79 35 6b 61 58 49 77 4d 46 77 } //01 00  V0VSOW1zby5kaXIwMFw
		$a_01_5 = {25 00 63 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 25 00 6c 00 73 00 5c 00 } //01 00  %c:\Program Files\%ls\
		$a_01_6 = {55 6e 52 73 51 57 52 71 64 58 4e 30 55 48 4a 70 64 6d 6c 73 5a 57 64 6c } //00 00  UnRsQWRqdXN0UHJpdmlsZWdl
	condition:
		any of ($a_*)
 
}