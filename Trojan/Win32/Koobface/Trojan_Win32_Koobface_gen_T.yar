
rule Trojan_Win32_Koobface_gen_T{
	meta:
		description = "Trojan:Win32/Koobface.gen!T,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {23 42 4c 41 43 4b 4c 41 42 45 4c } //01 00  #BLACKLABEL
		$a_01_1 = {62 6c 6f 67 67 65 72 2e 63 6f 6d 2f } //01 00  blogger.com/
		$a_01_2 = {62 6c 6f 67 73 70 6f 74 2e 63 6f 6d 2f } //01 00  blogspot.com/
		$a_01_3 = {2f 41 63 63 6f 75 6e 74 52 65 63 6f 76 65 72 79 4f 70 74 69 6f 6e 73 50 72 6f 6d 70 74 } //01 00  /AccountRecoveryOptionsPrompt
		$a_01_4 = {63 3a 5c 67 6f 6f 67 6c 65 72 65 67 6a 73 2e 62 61 74 } //01 00  c:\googleregjs.bat
		$a_01_5 = {3a 52 65 70 65 61 74 20 0a 20 64 65 6c 20 22 25 73 22 20 0a 20 69 66 20 65 78 69 73 74 20 } //00 00 
	condition:
		any of ($a_*)
 
}