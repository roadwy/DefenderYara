
rule Trojan_Win32_Ursnif_AP_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b7 4c 24 10 0f b6 f2 2b f0 81 c6 ?? ?? ?? ?? 3b f1 8a 4c 24 10 } //1
		$a_02_1 = {0f b7 5c 24 10 0f b6 fa 8b f0 2b f7 03 dd 83 c6 ?? 33 ff } //1
		$a_02_2 = {0f a4 f7 01 2b c8 81 e9 ?? ?? ?? ?? 03 f6 33 db 03 f1 13 fb 89 35 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 81 c5 ?? ?? ?? ?? 89 2a } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}