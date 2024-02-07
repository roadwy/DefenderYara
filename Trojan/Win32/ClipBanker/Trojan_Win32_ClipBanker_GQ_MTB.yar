
rule Trojan_Win32_ClipBanker_GQ_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 38 35 2e 32 31 35 2e 31 31 33 2e 38 } //01 00  185.215.113.8
		$a_01_1 = {74 73 72 76 33 2e 72 75 } //01 00  tsrv3.ru
		$a_01_2 = {74 73 72 76 34 2e 77 73 } //01 00  tsrv4.ws
		$a_01_3 = {74 6c 64 72 62 6f 78 2e 74 6f 70 } //01 00  tldrbox.top
		$a_01_4 = {74 6c 64 72 68 61 75 73 2e 74 6f 70 } //01 00  tldrhaus.top
		$a_01_5 = {74 6c 64 72 7a 6f 6e 65 2e 74 6f 70 } //01 00  tldrzone.top
		$a_80_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //Software\Microsoft\Windows\CurrentVersion\Run  01 00 
		$a_01_7 = {62 69 74 63 6f 69 6e 63 61 73 68 3a 71 70 78 37 67 32 66 79 75 77 71 34 38 6e 70 63 33 6d 73 63 75 7a 72 30 34 7a 36 6b 6e 6e 6b 6a 30 73 77 63 79 34 65 30 78 6a } //01 00  bitcoincash:qpx7g2fyuwq48npc3mscuzr04z6knnkj0swcy4e0xj
		$a_01_8 = {63 6f 73 6d 6f 73 31 66 77 33 78 39 61 74 6e 32 76 77 7a 75 76 6d 73 6d 35 37 78 77 64 36 71 30 6b 65 76 32 6b 71 64 75 6e 39 61 66 74 } //01 00  cosmos1fw3x9atn2vwzuvmsm57xwd6q0kev2kqdun9aft
		$a_01_9 = {62 61 6e 64 31 63 78 70 30 64 34 79 72 64 79 6c 6d 39 33 6e 6c 33 6c 35 78 64 6a 6d 6c 75 64 66 74 64 34 39 6e 66 36 6c 78 37 35 } //00 00  band1cxp0d4yrdylm93nl3l5xdjmludftd49nf6lx75
	condition:
		any of ($a_*)
 
}