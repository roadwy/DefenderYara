
rule Trojan_Win64_TrickBot_CO_MTB{
	meta:
		description = "Trojan:Win64/TrickBot.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 ?? 48 8b 4c 24 ?? 48 03 c8 48 8b c1 8a 40 01 88 44 24 ?? 0f b6 44 24 ?? 83 e8 ?? 6b c0 ?? ba 7f 00 00 00 8b c8 e8 ?? ?? ?? ?? 48 8b 4c 24 ?? 48 8b 54 24 ?? 48 03 d1 48 8b ca 88 41 01 eb a8 } //1
		$a_03_1 = {99 b9 7f 00 00 00 f7 f9 8b c2 88 44 24 ?? b8 01 00 00 00 48 6b c0 01 48 8d 0d ?? ?? ?? ?? 0f b6 04 01 6b c0 ?? 83 c0 ?? 99 b9 7f 00 00 00 f7 f9 8b c2 88 44 24 ?? b8 01 00 00 00 48 6b c0 02 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}