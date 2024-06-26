
rule PWS_Win32_Dyzap_A_{
	meta:
		description = "PWS:Win32/Dyzap.A!!Dyzap.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 } //01 00  %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X
		$a_01_1 = {62 6f 74 69 64 00 00 00 62 74 69 64 00 00 00 00 63 63 73 72 00 00 00 00 64 70 73 72 00 00 00 00 62 74 6e 74 00 00 00 00 73 6c 69 70 } //01 00 
		$a_01_2 = {41 55 54 4f 42 41 43 4b 43 4f 4e 4e } //01 00  AUTOBACKCONN
		$a_01_3 = {73 65 6e 64 20 62 72 6f 77 73 65 72 20 73 6e 61 70 73 68 6f 74 20 66 61 69 6c 65 64 } //01 00  send browser snapshot failed
		$a_01_4 = {73 65 6e 64 20 73 79 73 74 65 6d 20 69 6e 66 6f 20 66 61 69 6c 65 64 } //01 00  send system info failed
		$a_00_5 = {73 00 74 00 75 00 6e 00 31 00 2e 00 76 00 6f 00 69 00 63 00 65 00 65 00 63 00 6c 00 69 00 70 00 73 00 65 00 2e 00 6e 00 65 00 74 00 } //01 00  stun1.voiceeclipse.net
		$a_01_6 = {69 63 61 6e 68 61 7a 69 70 2e 63 6f 6d } //05 00  icanhazip.com
	condition:
		any of ($a_*)
 
}