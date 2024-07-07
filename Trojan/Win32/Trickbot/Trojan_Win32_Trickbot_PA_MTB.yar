
rule Trojan_Win32_Trickbot_PA_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 40 08 2b c6 3b c8 74 90 01 01 83 7d 90 01 01 10 8b 5d 90 01 01 72 90 01 01 8b 7d 04 eb 90 01 01 8d 7d 04 33 d2 8b c1 f7 f3 8a 04 3a 30 04 0e 41 eb 90 00 } //1
		$a_00_1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 } //1 C:\ProgramData\
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}