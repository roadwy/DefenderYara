
rule Trojan_Win32_Amadey_NMJ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.NMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 6c 24 10 89 74 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? ?? 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 31 4c 24 ?? 8b f3 c1 ee ?? 03 74 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 } //1
		$a_03_1 = {6a 00 ff 15 ?? ?? ?? ?? 8b 54 24 ?? 52 56 8d 44 24 ?? 50 e8 ?? ?? ?? ?? 2b 7c 24 ?? 81 44 24 ?? ?? ?? ?? ?? 83 6c 24 ?? ?? 89 7c 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}