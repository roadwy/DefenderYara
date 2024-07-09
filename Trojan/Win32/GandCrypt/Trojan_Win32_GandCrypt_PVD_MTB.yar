
rule Trojan_Win32_GandCrypt_PVD_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d0 89 15 ?? ?? ?? ?? 81 f9 66 0d 00 00 73 90 09 0d 00 0f b6 81 ?? ?? ?? ?? 03 05 } //1
		$a_02_1 = {30 04 2e 83 ee 01 79 90 09 05 00 e8 } //1
		$a_02_2 = {8b ce 8b c6 c1 e1 04 03 0d ?? ?? ?? ?? c1 e8 05 03 05 ?? ?? ?? ?? 33 c8 8d 04 37 2b 7d fc } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*2) >=2
 
}