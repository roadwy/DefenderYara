
rule Trojan_Win32_Adialer_gen_A{
	meta:
		description = "Trojan:Win32/Adialer_gen.A,SIGNATURE_TYPE_PEHSTR,17 00 14 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {83 fa 40 75 07 83 65 f4 00 8b 55 f4 8b c2 c1 f8 04 c0 e1 02 0a c1 8b c8 8b 45 0c 88 08 8b cb c0 e3 06 0a 5d fc 83 c0 03 c1 f9 02 c0 e2 04 0a ca 88 58 ff 88 48 fe 89 45 0c 8a 07 84 c0 0f 85 34 ff ff ff } //0a 00 
		$a_01_1 = {72 74 61 59 44 6a 77 4c 67 23 66 43 53 34 45 39 6e 71 56 6b 68 73 63 4f 48 62 76 6d 33 52 4a 35 36 78 70 54 5a 49 37 6c 58 69 2b 57 47 6f 32 4d 75 38 4b 51 42 31 64 50 55 41 4e 7a 65 30 46 79 } //01 00  rtaYDjwLg#fCS4E9nqVkhscOHbvm3RJ56xpTZI7lXi+WGo2Mu8KQB1dPUANze0Fy
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 79 73 74 65 6d 43 65 72 74 69 66 69 63 61 74 65 73 5c 54 72 75 73 74 65 64 50 75 62 6c 69 73 68 65 72 5c 43 65 72 74 69 66 69 63 61 74 65 73 } //01 00  Software\Microsoft\SystemCertificates\TrustedPublisher\Certificates
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 54 72 75 73 74 5c 54 72 75 73 74 20 50 72 6f 76 69 64 65 72 73 5c 53 6f 66 74 77 61 72 65 20 50 75 62 6c 69 73 68 69 6e 67 5c 54 72 75 73 74 20 44 61 74 61 62 61 73 65 5c 30 } //01 00  Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\Trust Database\0
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 5a 6f 6e 65 73 5c 33 } //01 00  Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //01 00  Software\Microsoft\Internet Explorer\Main
		$a_01_6 = {45 72 72 6f 72 65 20 6e 65 6c 20 72 69 6c 61 73 63 69 6f 20 64 65 6c 20 63 65 72 74 69 66 69 63 61 74 6f 20 64 69 20 61 74 74 69 76 61 7a 69 6f 6e 65 2e } //00 00  Errore nel rilascio del certificato di attivazione.
	condition:
		any of ($a_*)
 
}