
rule Trojan_Win32_Slenkill_gen_A{
	meta:
		description = "Trojan:Win32/Slenkill.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 7d f8 08 7d 39 8b 4d 08 03 4d f8 0f be 91 ?? ?? ?? ?? 33 55 fc 8b 45 f4 03 45 f8 88 10 8b 4d fc 83 c1 01 89 4d fc 8b 55 fc 81 e2 ff 00 00 80 79 08 } //1
		$a_03_1 = {6a 64 ff 15 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? 8d 4d ?? e8 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? c7 45 ?? 00 00 00 00 eb 09 8b 4d ?? 83 c1 01 89 4d ?? 83 7d ?? 18 7d 0a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}