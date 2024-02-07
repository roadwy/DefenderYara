
rule Trojan_Win32_Zbot_DV_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 61 76 65 2e 64 6c 6c } //01 00  Save.dll
		$a_01_1 = {47 65 74 54 65 6d 70 50 61 74 68 57 } //01 00  GetTempPathW
		$a_81_2 = {63 3a 5c 63 72 79 70 74 6f 72 5c 63 72 79 70 74 6f 72 64 6c 6c 5c 62 69 6e 5c 6a 73 6f 6e 2e 68 } //01 00  c:\cryptor\cryptordll\bin\json.h
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_4 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 57 } //01 00  OutputDebugStringW
		$a_81_5 = {42 69 74 20 53 68 65 6f 76 65 72 20 54 6f 74 61 6c 66 61 74 68 65 72 } //00 00  Bit Sheover Totalfather
	condition:
		any of ($a_*)
 
}