
rule Trojan_Win32_KeyLogger_J_bit{
	meta:
		description = "Trojan:Win32/KeyLogger.J!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //1 software\microsoft\windows\currentversion\run
		$a_03_1 = {0f b6 54 32 ff 66 33 d3 0f b7 d2 2b d6 33 d6 2b d6 33 d6 88 54 30 ff 43 8b 45 90 01 01 e8 90 01 04 0f b7 f3 3b c6 7f 90 00 } //1
		$a_01_2 = {8d 74 31 fc 8d 7c 39 fc c1 f9 02 78 11 fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}