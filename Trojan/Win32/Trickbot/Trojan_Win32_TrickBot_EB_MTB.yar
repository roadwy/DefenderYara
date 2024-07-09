
rule Trojan_Win32_TrickBot_EB_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {2b da 8b fa 89 5d ?? 89 4d 08 8b ff 8a 0c 3b 80 f1 20 8b c7 3b fe 73 1b 8d 64 ?? ?? 8a d8 2a da 80 e3 20 32 18 32 d9 88 18 03 45 ?? 3b c6 72 ec 8b 5d ?? 47 ff 4d 08 75 } //1
		$a_02_1 = {23 d1 8a 06 88 07 8a 46 01 88 47 01 8a 46 02 c1 e9 02 88 47 02 83 c6 03 83 c7 03 83 f9 08 72 [0-15] 23 d1 8a 06 88 07 8a 46 01 c1 e9 02 88 47 01 83 c6 02 83 c7 02 83 f9 08 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}