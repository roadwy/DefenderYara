
rule Trojan_Win32_CryptInject_PC_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 ?? ?? ?? 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? 00 e8 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c 90 09 08 00 81 ff ?? ?? 00 00 75 } //1
		$a_02_1 = {6a 00 ff 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 69 c0 fd 43 03 00 56 a3 ?? ?? ?? 00 81 05 ?? ?? ?? 00 c3 9e 26 00 81 3d ?? ?? ?? 00 ?? ?? 00 00 0f b7 35 ?? ?? ?? 00 75 ?? 6a 00 6a 00 ff 15 ?? ?? ?? 00 8b c6 25 ff 7f 00 00 5e c3 90 09 0c 00 81 3d ?? ?? ?? 00 ?? ?? 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}