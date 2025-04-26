
rule TrojanSpy_Win32_Usteal_C{
	meta:
		description = "TrojanSpy:Win32/Usteal.C,SIGNATURE_TYPE_PEHSTR,10 00 10 00 09 00 00 "
		
	strings :
		$a_01_0 = {55 46 52 5f 53 74 65 61 6c 65 72 5f } //10 UFR_Stealer_
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //1 encryptedUsername, encryptedPassword FROM moz_logins
		$a_01_2 = {4f 70 65 72 61 5c 77 61 6e 64 2e 64 61 74 } //1 Opera\wand.dat
		$a_01_3 = {47 68 69 73 6c 65 72 5c 54 6f 74 61 6c 20 43 6f 6d 6d 61 6e 64 65 72 } //1 Ghisler\Total Commander
		$a_01_4 = {2e 70 75 72 70 6c 65 5c 61 63 63 6f 75 6e 74 73 2e 78 6d 6c } //1 .purple\accounts.xml
		$a_01_5 = {47 6f 6f 67 6c 65 20 54 61 6c 6b 5c 41 63 63 6f 75 6e 74 73 } //1 Google Talk\Accounts
		$a_01_6 = {25 30 32 68 75 2d 25 30 32 68 75 2d 25 68 75 5f 25 30 32 68 75 2d 25 30 32 68 75 2d 25 30 32 68 75 5f 25 73 } //1 %02hu-%02hu-%hu_%02hu-%02hu-%02hu_%s
		$a_01_7 = {52 65 67 69 73 74 72 79 2d 47 72 61 62 62 69 6e 67 2e 72 65 67 } //1 Registry-Grabbing.reg
		$a_01_8 = {64 6f 6b 6f 74 61 61 61 61 2e 68 6f 70 2e 72 75 } //1 dokotaaaa.hop.ru
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=16
 
}