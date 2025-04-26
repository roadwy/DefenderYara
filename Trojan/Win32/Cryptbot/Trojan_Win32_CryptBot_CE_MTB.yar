
rule Trojan_Win32_CryptBot_CE_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 8a 44 05 10 88 04 0a b9 ?? ?? ?? ?? 6b d1 ?? b8 ?? ?? ?? ?? 6b c8 ?? 8b 45 fc 8a 54 15 10 88 14 08 b8 ?? ?? ?? ?? d1 ?? b9 ?? ?? ?? ?? d1 ?? 8b 55 fc 8a 44 05 10 88 04 0a b9 ?? ?? ?? ?? 6b d1 03 b8 ?? ?? ?? ?? 6b c8 03 8b 45 fc 8a 54 15 10 88 14 08 } //5
		$a_81_1 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //3 ResumeThread
		$a_81_2 = {47 65 74 54 68 72 65 61 64 54 69 6d 65 73 } //2 GetThreadTimes
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*3+(#a_81_2  & 1)*2) >=10
 
}