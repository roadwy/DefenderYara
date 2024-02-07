
rule Spammer_Win32_Talwadig_A{
	meta:
		description = "Spammer:Win32/Talwadig.A,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 14 00 00 03 00 "
		
	strings :
		$a_01_0 = {50 6f 73 68 65 6c 2d 6b 61 20 74 69 20 6e 61 20 68 75 69 20 64 72 75 67 20 61 76 65 72 } //02 00  Poshel-ka ti na hui drug aver
		$a_01_1 = {42 4f 54 5f 48 4f 53 54 } //01 00  BOT_HOST
		$a_01_2 = {45 48 4c 4f 20 7b 4d 59 53 45 52 56 45 52 7d } //01 00  EHLO {MYSERVER}
		$a_01_3 = {7b 4d 41 49 4c 54 4f 5f 4e 41 4d 45 7d 20 3c 7b 4d 41 49 4c 5f 54 4f 7d 3e } //01 00  {MAILTO_NAME} <{MAIL_TO}>
		$a_01_4 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c 7b 4d 41 49 4c 5f 46 52 4f 4d 7d 3e } //01 00  MAIL FROM:<{MAIL_FROM}>
		$a_01_5 = {52 43 50 54 20 54 4f 3a 20 3c 7b 4d 41 49 4c 5f 54 4f 7d 3e } //01 00  RCPT TO: <{MAIL_TO}>
		$a_01_6 = {4d 41 49 4c 46 52 4f 4d 5f } //01 00  MAILFROM_
		$a_01_7 = {4d 41 49 4c 54 4f 5f } //01 00  MAILTO_
		$a_01_8 = {54 41 47 4d 41 49 4c 46 52 4f 4d } //01 00  TAGMAILFROM
		$a_01_9 = {65 78 74 5f 69 70 } //01 00  ext_ip
		$a_01_10 = {46 4f 52 20 76 61 72 69 61 62 6c 65 20 3d 20 30 20 54 4f 20 41 54 54 41 43 48 43 4f 55 4e 54 } //01 00  FOR variable = 0 TO ATTACHCOUNT
		$a_01_11 = {52 4f 54 00 42 41 53 45 36 34 } //01 00  佒T䅂䕓㐶
		$a_01_12 = {6d 78 73 2e 6d 61 69 6c 2e 72 75 } //01 00  mxs.mail.ru
		$a_01_13 = {67 6d 61 69 6c 2d 73 6d 74 70 2d 69 6e 2e 6c 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //01 00  gmail-smtp-in.l.google.com
		$a_01_14 = {6d 61 69 6c 37 2e 64 69 67 69 74 61 6c 77 61 76 65 73 2e 63 6f 2e 6e 7a } //01 00  mail7.digitalwaves.co.nz
		$a_01_15 = {72 65 61 64 20 6d 61 63 72 6f 73 65 73 2e } //01 00  read macroses.
		$a_01_16 = {31 39 39 2e 32 2e 32 35 32 2e 31 30 } //01 00  199.2.252.10
		$a_01_17 = {32 30 34 2e 39 37 2e 32 31 32 2e 31 30 } //01 00  204.97.212.10
		$a_01_18 = {36 34 2e 31 30 32 2e 32 35 35 2e 34 34 } //01 00  64.102.255.44
		$a_01_19 = {31 32 38 2e 31 30 37 2e 32 34 31 2e 31 38 35 } //00 00  128.107.241.185
	condition:
		any of ($a_*)
 
}