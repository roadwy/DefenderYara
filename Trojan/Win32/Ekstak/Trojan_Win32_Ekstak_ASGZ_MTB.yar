
rule Trojan_Win32_Ekstak_ASGZ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 14 09 8b 0d ?? ?? 65 00 0b d1 89 54 24 04 df 6c 24 04 dc 05 ?? ?? 65 00 dd 1d ?? ?? 65 00 ff 15 ?? ?? 65 00 a1 ?? ?? ?? 00 50 ff 15 ?? ?? 65 00 68 ?? ?? 65 00 ff 15 ?? ?? 65 00 b8 01 00 00 00 83 c4 08 c3 } //4
		$a_03_1 = {83 ec 08 a1 [0-09] 00 8b 0d 30 ?? ?? 00 50 c7 44 24 08 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}