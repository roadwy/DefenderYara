
rule Trojan_Win64_Trickbot_CK_MTB{
	meta:
		description = "Trojan:Win64/Trickbot.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 48 60 73 65 00 b9 f8 2a 00 00 ff 15 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 85 c0 74 eb c7 44 24 ?? 53 65 6c 65 8b 44 24 ?? ff c0 89 44 24 ?? c7 44 24 ?? 57 61 6e 74 8b 44 24 ?? ff c8 } //1
		$a_81_1 = {52 65 6c 65 61 73 65 } //1 Release
		$a_81_2 = {46 72 65 65 42 75 66 66 65 72 } //1 FreeBuffer
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}