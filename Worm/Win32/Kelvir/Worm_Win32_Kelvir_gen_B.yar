
rule Worm_Win32_Kelvir_gen_B{
	meta:
		description = "Worm:Win32/Kelvir.gen!B,SIGNATURE_TYPE_PEHSTR,2a 00 2a 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4b 65 6c 56 69 72 } //0a 00  KelVir
		$a_01_1 = {54 00 68 00 65 00 20 00 52 00 50 00 4d 00 69 00 53 00 4f 00 20 00 47 00 72 00 6f 00 75 00 70 00 } //0a 00  The RPMiSO Group
		$a_01_2 = {6f 62 6a 6d 65 73 73 65 6e 67 65 72 } //0a 00  objmessenger
		$a_01_3 = {4d 65 73 73 65 6e 67 65 72 41 50 49 } //01 00  MessengerAPI
		$a_01_4 = {7b 00 45 00 4e 00 54 00 45 00 52 00 7d 00 } //01 00  {ENTER}
		$a_01_5 = {7e 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 65 73 73 65 6e 67 65 72 5c 6d 73 6d 73 67 73 2e 65 78 65 5c 33 } //01 00  ~C:\Program Files\Messenger\msmsgs.exe\3
		$a_01_6 = {7e 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 53 4e 20 4d 65 73 73 65 6e 67 65 72 5c 6d 73 6e 6d 73 67 72 2e 65 78 65 5c 32 } //00 00  ~C:\Program Files\MSN Messenger\msnmsgr.exe\2
	condition:
		any of ($a_*)
 
}