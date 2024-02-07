
rule Trojan_Win32_Dahrwam_A{
	meta:
		description = "Trojan:Win32/Dahrwam.A,SIGNATURE_TYPE_PEHSTR_EXT,2d 01 2d 01 0f 00 00 64 00 "
		
	strings :
		$a_00_0 = {65 3a 5c 77 6f 72 6b 5c 6d 61 6c 77 61 72 5c 68 61 72 64 5c 45 6e 67 69 6e 65 44 6c 6c 5c 72 65 6c 65 61 73 65 5c 45 6e 67 69 6e 65 44 6c 6c 2e 70 64 62 } //64 00  e:\work\malwar\hard\EngineDll\release\EngineDll.pdb
		$a_00_1 = {43 4f 4d 52 50 43 4d 75 74 65 78 30 } //64 00  COMRPCMutex0
		$a_02_2 = {55 8b ec 83 ec 10 56 57 be 90 01 04 8d 7d f0 a5 a5 6a 0c 8d 45 f0 50 a5 6a 75 58 a4 e8 90 01 04 59 59 8d 45 f0 50 6a 01 6a 00 ff 15 90 01 04 8b f0 85 f6 74 13 e8 90 01 04 56 ff 15 90 01 04 56 ff 15 90 01 04 5f 33 c0 5e c9 c2 04 00 90 00 } //01 00 
		$a_00_3 = {68 74 74 70 3a 2f 2f 38 31 2e 39 35 2e 31 34 34 2e 32 34 32 2f 74 65 73 2f 63 6f 75 74 2e 70 68 70 } //01 00  http://81.95.144.242/tes/cout.php
		$a_00_4 = {2f 72 70 63 2f 63 6c 2e 70 68 70 } //01 00  /rpc/cl.php
		$a_00_5 = {67 65 57 65 62 32 20 41 67 65 6e 74 20 31 2e 30 } //01 00  geWeb2 Agent 1.0
		$a_00_6 = {5c 5c 2e 5c 6b 63 70 } //01 00  \\.\kcp
		$a_00_7 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 00 73 76 63 68 6f 73 74 00 00 73 76 63 68 6f 73 74 } //01 00 
		$a_00_8 = {45 6e 67 69 6e 65 44 6c 6c 2e 64 6c 6c 00 57 61 69 74 46 6f 72 45 78 69 74 } //01 00 
		$a_00_9 = {6d 78 73 2e 6d 61 69 6c 2e 72 75 } //01 00  mxs.mail.ru
		$a_00_10 = {67 6d 61 69 6c 2d 73 6d 74 70 2d 69 6e 2e 6c 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //01 00  gmail-smtp-in.l.google.com
		$a_00_11 = {67 73 6d 74 70 31 38 33 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //01 00  gsmtp183.google.com
		$a_00_12 = {69 6e 31 2e 73 6d 74 70 2e 6d 65 73 73 61 67 69 6e 67 65 6e 67 69 6e 65 2e 63 6f 6d } //01 00  in1.smtp.messagingengine.com
		$a_00_13 = {6d 61 69 6c 37 2e 64 69 67 69 74 61 6c 77 61 76 65 73 2e 63 6f 2e 6e 7a } //03 00  mail7.digitalwaves.co.nz
		$a_02_14 = {33 db 53 66 89 45 f0 6a 08 8d 45 ec 50 ff 75 08 66 c7 45 ec 0b 01 66 89 5d f2 e8 90 01 04 83 f8 08 74 08 83 c8 ff e9 c8 00 00 00 53 6a 02 8d 45 f8 50 ff 75 08 e8 90 01 04 83 f8 02 75 e4 66 81 7d f8 0b 01 75 dc 53 50 8d 45 fc 50 ff 75 08 e8 90 01 04 83 f8 02 75 c9 f6 45 fc 80 74 11 53 6a 06 57 ff 75 08 e8 90 01 04 83 f8 06 75 b2 f6 45 fc 40 6a 04 5f 74 0f 53 57 56 ff 75 08 e8 90 01 04 3b c7 75 9a f6 45 fc 01 74 54 53 57 8d 45 f4 50 ff 75 08 e8 90 01 04 3b c7 75 82 57 68 00 10 00 00 ff 75 f4 53 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}