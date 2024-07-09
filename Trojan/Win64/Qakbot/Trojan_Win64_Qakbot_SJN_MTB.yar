
rule Trojan_Win64_Qakbot_SJN_MTB{
	meta:
		description = "Trojan:Win64/Qakbot.SJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff c1 38 5c 0d ?? 75 ?? b8 ?? ?? ?? ?? 3b c8 0f 47 c8 85 c9 74 ?? 48 ?? ?? ?? 8d 43 ?? ff c3 88 02 48 ?? ?? 3b d9 72 } //1
		$a_03_1 = {4c 8b c0 44 8b ce 33 d2 41 8b c6 41 f7 f4 42 8a 0c 2a 43 32 0c 3e 41 ff c6 41 88 08 49 ff c0 49 83 e9 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}