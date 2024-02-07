
rule Spammer_Win32_Nuwar_A{
	meta:
		description = "Spammer:Win32/Nuwar.A,SIGNATURE_TYPE_PEHSTR,0b 00 09 00 0a 00 00 02 00 "
		
	strings :
		$a_01_0 = {75 07 41 80 3c 08 00 75 e8 80 39 00 74 13 ff 45 08 8b 4d 08 8a 11 40 84 d2 75 d0 } //02 00 
		$a_01_1 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 22 25 73 } //02 00  netsh firewall set allowedprogram "%s
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {73 79 73 69 6e 74 65 72 00 } //01 00 
		$a_01_4 = {32 32 31 20 43 6c 6f 73 69 6e 67 20 63 6f 6e 6e 65 63 74 69 6f 6e 2e 20 47 6f 6f 64 20 62 79 65 2e } //01 00  221 Closing connection. Good bye.
		$a_01_5 = {35 35 30 20 52 65 6c 61 79 20 44 65 6e 69 65 64 } //01 00  550 Relay Denied
		$a_01_6 = {72 63 70 74 20 74 6f } //01 00  rcpt to
		$a_01_7 = {32 35 30 20 53 65 6e 64 65 72 20 6f 6b } //01 00  250 Sender ok
		$a_01_8 = {6d 61 69 6c 20 66 72 6f 6d } //01 00  mail from
		$a_01_9 = {32 35 30 20 48 65 6c 6c 6f 2c 20 70 6c 65 61 73 65 64 20 74 6f 20 6d 65 65 74 20 79 6f 75 } //00 00  250 Hello, pleased to meet you
	condition:
		any of ($a_*)
 
}