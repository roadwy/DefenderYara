
rule Trojan_Win32_MBRLock_EQ_MTB{
	meta:
		description = "Trojan:Win32/MBRLock.EQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {16 9e 49 00 3a ab 49 00 ff ae 49 00 93 b1 49 00 b4 b1 49 00 45 e7 48 00 90 a8 40 00 50 27 41 00 90 33 41 } //03 00 
		$a_01_1 = {bd 9e 49 00 35 9f 49 00 6d 9f 49 00 39 25 49 00 4f 25 49 00 8d 25 49 00 cb 25 49 00 09 26 49 00 d4 9c 49 00 d8 a6 49 } //02 00 
		$a_01_2 = {59 6f 75 72 20 64 69 73 6b 20 68 61 76 65 20 61 20 6c 6f 63 6b 21 21 21 50 6c 65 61 73 65 20 65 6e 74 65 72 20 74 68 65 20 75 6e 6c 6f 63 6b 20 70 61 73 73 77 6f 72 64 } //00 00  Your disk have a lock!!!Please enter the unlock password
	condition:
		any of ($a_*)
 
}