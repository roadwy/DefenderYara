
rule Trojan_Win32_Fragtor_SIBA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 6e 00 61 00 6d 00 65 00 20 00 75 00 6e 00 6b 00 6e 00 6f 00 77 00 6e 00 3e 00 } //1 <program name unknown>
		$a_03_1 = {6a 40 68 00 ?? ?? ?? 8b 55 ?? 52 6a 00 ff 15 ?? ?? ?? ?? 89 45 ?? 6a 00 8d 45 ?? 50 8b 4d 90 1b 01 51 8b 55 90 1b 03 52 8b 45 ?? 50 ff 15 ?? ?? ?? ?? c7 45 ?? 00 00 00 00 90 18 8b 55 90 1b 09 3b 55 90 1b 01 90 18 6a 00 6a 00 8b 45 90 1b 03 50 ff 15 } //1
		$a_03_2 = {88 0a 8b 45 ?? 03 45 ?? 0f b6 08 81 c1 ?? ?? ?? ?? 8b 55 90 1b 00 03 55 90 1b 01 88 0a } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}