
rule Backdoor_Win32_Trickbot_MAK_MTB{
	meta:
		description = "Backdoor:Win32/Trickbot.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {6a 6f 65 62 6f 78 63 6f 6e 74 72 6f 6c 2e 65 78 65 } //joeboxcontrol.exe  01 00 
		$a_80_1 = {6a 6f 65 62 6f 78 73 65 72 76 65 72 2e 65 78 65 } //joeboxserver.exe  01 00 
		$a_80_2 = {43 68 65 63 6b 69 6e 67 20 70 72 6f 63 65 73 73 20 6f 66 20 6d 61 6c 77 61 72 65 20 61 6e 61 6c 79 73 69 73 20 74 6f 6f 6c 3a 20 25 73 } //Checking process of malware analysis tool: %s  05 00 
		$a_03_3 = {8b c7 8b 39 8b f7 c1 e8 90 02 01 c1 e6 90 02 01 0b f0 89 32 4b 83 c1 90 02 01 83 c2 90 02 01 f6 c3 07 75 e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}