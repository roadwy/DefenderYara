
rule Trojan_Win32_Trickbot_PSB_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.PSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {73 05 8a 4d 90 0a 0f 00 30 4c 05 90 01 01 40 83 f8 90 01 01 90 01 05 eb f1 90 00 } //01 00 
		$a_03_1 = {41 83 f9 09 73 05 8a 90 0a 0e 00 8d 04 90 01 01 30 44 0d 90 01 01 90 01 09 eb ee 90 00 } //01 00 
		$a_03_2 = {8d 04 0a 30 44 0d 90 01 01 41 83 f9 90 01 01 73 05 8a 55 90 01 01 eb ee 8d 90 00 } //01 00 
		$a_03_3 = {8d 04 0b 30 44 0d 90 01 01 41 83 f9 90 01 01 73 05 8a 55 90 01 01 eb ee 8d 90 00 } //0a 00 
		$a_00_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //0a 00  IsDebuggerPresent
		$a_00_5 = {46 6c 75 73 68 46 69 6c 65 42 75 66 66 65 72 73 } //00 00  FlushFileBuffers
	condition:
		any of ($a_*)
 
}