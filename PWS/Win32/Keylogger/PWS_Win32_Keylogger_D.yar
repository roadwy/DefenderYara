
rule PWS_Win32_Keylogger_D{
	meta:
		description = "PWS:Win32/Keylogger.D,SIGNATURE_TYPE_PEHSTR_EXT,14 00 13 00 08 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 89 44 24 04 c7 04 24 90 01 01 00 00 00 e8 90 01 02 00 00 8b 45 e8 89 04 24 e8 90 01 02 00 00 eb 90 01 01 8b 45 e8 89 44 24 04 c7 04 24 90 01 01 00 00 00 e8 90 01 02 00 00 8b 45 e8 89 04 24 e8 90 01 02 00 00 eb 90 00 } //02 00 
		$a_00_1 = {70 65 72 6f 78 79 64 65 2e 70 61 79 70 61 6c 40 67 6d 61 69 6c 2e 63 6f 6d } //02 00  peroxyde.paypal@gmail.com
		$a_00_2 = {68 65 6c 6f 20 6d 65 2e 73 6f 6d 65 70 61 6c 61 63 65 2e 63 6f 6d } //02 00  helo me.somepalace.com
		$a_00_3 = {53 74 61 72 74 65 64 20 6c 6f 67 67 69 6e 67 3a } //01 00  Started logging:
		$a_00_4 = {73 6f 75 6e 64 2e 77 61 76 } //01 00  sound.wav
		$a_00_5 = {67 6d 61 69 6c 2d 73 6d 74 70 2d 69 6e 2e 6c 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //01 00  gmail-smtp-in.l.google.com
		$a_00_6 = {52 43 50 54 20 54 4f 3a 3c } //01 00  RCPT TO:<
		$a_00_7 = {5b 43 41 50 53 20 4c 4f 43 4b 5d } //00 00  [CAPS LOCK]
	condition:
		any of ($a_*)
 
}