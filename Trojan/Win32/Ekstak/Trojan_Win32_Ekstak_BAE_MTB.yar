
rule Trojan_Win32_Ekstak_BAE_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 ec 08 a0 ?? ?? ?? 00 8a 0d ?? ?? ?? 00 32 c8 56 88 0d ?? ?? ?? 00 8a 0d ?? ?? ?? 00 80 c9 0c 68 ?? ?? ?? 00 c0 e9 02 81 e1 ff 00 00 00 89 4c 24 08 } //4
		$a_03_1 = {83 ec 08 a0 ?? ?? ?? 00 8a 0d ?? ?? ?? 00 32 c8 8d 54 24 00 88 0d ?? ?? ?? 00 8a 0d ?? ?? ?? 00 80 c9 0c 52 c0 e9 02 81 e1 ff } //4
		$a_03_2 = {55 8b ec 83 ec 18 53 56 57 e8 ?? ?? ?? ff 89 45 fc e9 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4+(#a_03_2  & 1)*1) >=5
 
}