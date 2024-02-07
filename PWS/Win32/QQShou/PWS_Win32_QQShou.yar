
rule PWS_Win32_QQShou{
	meta:
		description = "PWS:Win32/QQShou,SIGNATURE_TYPE_PEHSTR,07 00 07 00 0e 00 00 02 00 "
		
	strings :
		$a_01_0 = {58 2d 4d 61 69 6c 65 72 3a 20 51 71 47 68 6f 73 74 20 5b 63 68 5d } //02 00  X-Mailer: QqGhost [ch]
		$a_01_1 = {58 2d 4d 61 69 6c 65 72 3a 20 4c 43 4d 61 69 6c 65 72 20 5b 63 68 5d } //02 00  X-Mailer: LCMailer [ch]
		$a_01_2 = {22 00 00 00 72 66 77 6d 61 69 6e 00 } //01 00 
		$a_01_3 = {41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 30 31 32 33 34 35 36 37 38 39 2b 2f } //01 00  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
		$a_01_4 = {77 77 77 2e 63 68 75 61 6e 68 75 61 2e 6e 65 74 } //01 00  www.chuanhua.net
		$a_01_5 = {63 68 75 61 6e 68 75 61 2e 6e 65 61 73 65 2e 6e 65 74 } //01 00  chuanhua.nease.net
		$a_01_6 = {52 43 50 54 20 54 4f 3a 3c 25 73 3e } //01 00  RCPT TO:<%s>
		$a_01_7 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c 25 73 3e } //01 00  MAIL FROM:<%s>
		$a_01_8 = {00 74 65 6d 70 7e 33 00 } //01 00  琀浥繰3
		$a_01_9 = {47 65 74 50 69 78 65 6c } //f1 ff  GetPixel
		$a_01_10 = {43 61 70 74 75 72 65 2e 64 6c 6c } //f1 ff  Capture.dll
		$a_01_11 = {4d 65 64 69 61 54 72 61 6e 73 6d 69 74 2e 64 6c 6c } //f1 ff  MediaTransmit.dll
		$a_01_12 = {4e 65 74 44 69 73 6b 44 4c 4c 2e 64 6c 6c 00 42 61 73 65 36 34 44 65 63 6f 64 65 00 } //f1 ff  敎䑴獩䑫䱌搮汬䈀獡㙥䐴捥摯e
		$a_01_13 = {50 6f 6c 69 63 79 4d 61 6e 61 67 65 2e 64 6c 6c } //00 00  PolicyManage.dll
	condition:
		any of ($a_*)
 
}