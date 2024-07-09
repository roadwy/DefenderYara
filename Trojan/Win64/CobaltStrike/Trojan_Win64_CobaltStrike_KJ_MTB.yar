
rule Trojan_Win64_CobaltStrike_KJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 20 04 00 00 00 41 b9 00 10 00 00 41 b8 90 00 00 00 48 8b ce ff 15 } //1
		$a_01_1 = {6c 65 67 61 63 79 2e 63 68 75 6e 6b 2e 6a 73 } //1 legacy.chunk.js
		$a_03_2 = {77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c [0-02] 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Trojan_Win64_CobaltStrike_KJ_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.KJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff c0 89 85 ?? ?? ?? ?? 8b 45 ?? 39 85 ?? ?? ?? ?? 7d ?? 8b 85 ?? ?? ?? ?? 83 c0 ?? 99 f7 7d ?? 8b c2 89 85 } //1
		$a_03_1 = {0f be 0c 0a 33 c1 48 63 8d ?? ?? ?? ?? 48 8b 95 ?? ?? ?? ?? 88 04 0a eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}