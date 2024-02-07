
rule PWS_Win32_XSpy_A{
	meta:
		description = "PWS:Win32/XSpy.A,SIGNATURE_TYPE_PEHSTR,4e 00 4e 00 11 00 00 0a 00 "
		
	strings :
		$a_01_0 = {25 32 5c 49 6e 73 65 72 74 61 62 6c 65 } //0a 00  %2\Insertable
		$a_01_1 = {43 4c 53 49 44 5c 25 31 5c 41 75 78 55 73 65 72 54 79 70 65 5c } //0a 00  CLSID\%1\AuxUserType\
		$a_01_2 = {58 2d 4d 61 69 6c 65 72 3a 20 } //0a 00  X-Mailer: 
		$a_01_3 = {52 43 50 54 20 54 4f 3a 20 } //0a 00  RCPT TO: 
		$a_01_4 = {53 65 6e 64 20 6d 61 69 6c 20 65 6e 64 20 65 72 72 6f 72 } //0a 00  Send mail end error
		$a_01_5 = {50 61 73 73 77 6f 72 64 20 65 72 72 6f 72 } //0a 00  Password error
		$a_01_6 = {75 6e 48 6f 6f 6b } //01 00  unHook
		$a_01_7 = {63 3a 5c 78 6c 77 6a } //01 00  c:\xlwj
		$a_01_8 = {41 4c 54 20 2b 20 43 54 4c 20 2b 20 4b } //01 00  ALT + CTL + K
		$a_01_9 = {78 6c 73 70 79 5f 73 6f 66 74 40 74 6f 6d 2e 63 6f 6d } //01 00  xlspy_soft@tom.com
		$a_01_10 = {5c 6d 73 63 6f 6e 2e 77 61 76 } //01 00  \mscon.wav
		$a_01_11 = {25 73 5c 70 72 64 2e 69 6e 69 } //01 00  %s\prd.ini
		$a_01_12 = {73 6d 74 70 2e 74 6f 6d 2e 63 6f 6d } //01 00  smtp.tom.com
		$a_01_13 = {67 62 32 33 31 32 } //01 00  gb2312
		$a_01_14 = {66 72 69 65 6e 64 31 } //01 00  friend1
		$a_01_15 = {6c 63 5f 73 70 79 64 6f 67 40 74 6f 6d 2e 63 6f 6d } //01 00  lc_spydog@tom.com
		$a_01_16 = {25 73 5c 73 70 72 63 2e 69 6e 69 } //00 00  %s\sprc.ini
	condition:
		any of ($a_*)
 
}