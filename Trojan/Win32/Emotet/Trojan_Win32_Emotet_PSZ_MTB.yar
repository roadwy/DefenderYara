
rule Trojan_Win32_Emotet_PSZ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PSZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 4c 24 ?? 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 83 c4 ?? 8a 4c 14 ?? 30 08 } //1
		$a_81_1 = {49 47 4c 69 56 4b 42 75 64 6e 74 4a 71 52 49 4a 4b 36 71 4a 47 46 4b 70 34 7a 4c 65 55 78 45 42 71 50 72 76 6d 56 58 51 54 } //1 IGLiVKBudntJqRIJK6qJGFKp4zLeUxEBqPrvmVXQT
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}