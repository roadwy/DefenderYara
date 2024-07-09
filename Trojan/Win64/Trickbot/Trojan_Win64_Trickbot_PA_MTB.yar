
rule Trojan_Win64_Trickbot_PA_MTB{
	meta:
		description = "Trojan:Win64/Trickbot.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {40 88 7c 24 ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? ?? 44 24 [0-10] 75 } //1
		$a_01_1 = {47 72 61 62 5f 50 61 73 73 77 6f 72 64 73 5f 43 68 72 6f 6d 65 } //1 Grab_Passwords_Chrome
		$a_01_2 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 48 69 73 74 6f 72 79 2e 62 61 6b } //1 \Google\Chrome\User Data\Default\History.bak
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}