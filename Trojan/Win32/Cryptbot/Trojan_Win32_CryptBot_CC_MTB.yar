
rule Trojan_Win32_CryptBot_CC_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c6 f7 75 08 8a 0c 1a 30 0c 3e 46 81 fe 90 01 04 72 90 00 } //05 00 
		$a_03_1 = {0f af d1 8b 4d 08 8b c1 56 8b 35 90 01 04 c1 e8 90 01 01 88 44 96 01 8b c1 88 0c 96 c1 e8 90 01 01 c1 e9 90 01 01 88 44 96 03 88 4c 96 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CryptBot_CC_MTB_2{
	meta:
		description = "Trojan:Win32/CryptBot.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 c1 2c 5d 34 4a 04 5d c0 c0 03 c0 c8 03 c0 c0 03 2c 5d 34 4a aa 4a 0f 85 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_3 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //00 00  GetTickCount
	condition:
		any of ($a_*)
 
}