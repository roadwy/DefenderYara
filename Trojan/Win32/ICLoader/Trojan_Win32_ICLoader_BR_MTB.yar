
rule Trojan_Win32_ICLoader_BR_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {56 8b f1 57 8a 0d ?? ?? ?? 00 6a 00 32 c8 88 0d ?? ?? ?? 00 8a 0d ?? ?? ?? 00 80 c9 0c c0 e9 02 81 e1 ff 00 00 00 89 4c 24 0c db 44 24 0c dc 3d } //5
		$a_03_1 = {53 56 57 6a 00 ff 15 ?? ?? ?? 00 8b 3d ?? ?? ?? 00 8b f0 6a 0c 56 ff d7 6a 0e 56 8b d8 ff d7 0f af c3 83 f8 08 56 0f 9e c0 6a 00 a2 } //5
		$a_03_2 = {c1 e9 02 8b ea 2b d9 8b 15 ?? ?? ?? 00 33 c9 8a 0d ?? ?? ?? 00 83 ca 07 0f af d1 23 c2 8b 15 ?? ?? ?? 00 57 52 89 1d ?? ?? ?? 00 a3 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 55 56 ff 15 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=5
 
}