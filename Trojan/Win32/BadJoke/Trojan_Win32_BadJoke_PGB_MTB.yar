
rule Trojan_Win32_BadJoke_PGB_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.PGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ca 8b c2 c1 e8 ?? c1 e9 ?? 32 c8 8b c2 c1 e8 ?? 0a c8 0f be c2 0f be c9 0f af c8 8a c1 02 c9 02 c1 c0 e0 ?? 88 84 15 ?? ?? ?? ?? 42 81 fa ?? ?? ?? ?? 72 } //5
		$a_03_1 = {8b ca 4d 8d 40 ?? c1 e9 ?? 8b c2 c1 e8 ?? 32 c8 8b c2 c1 e8 ?? 0a c8 0f be c2 0f be c9 ff c2 0f af c8 0f b6 c1 02 c0 02 c8 c0 e1 ?? 41 88 48 ?? 81 fa ?? ?? ?? ?? 72 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}