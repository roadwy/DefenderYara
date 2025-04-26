
rule Trojan_Win32_RemcosRAT_NCA_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.NCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {77 39 6a 09 e8 94 be ff ff 59 c7 45 fc ?? ?? ?? ?? 8b c6 c1 e8 04 50 e8 a0 e7 ff ff 59 89 45 e0 } //2
		$a_03_1 = {a1 30 e3 46 00 85 c0 74 22 8b 0d ?? ?? ?? ?? 56 8d 71 fc 3b f0 72 13 8b 06 85 c0 74 02 ff d0 } //2
		$a_01_2 = {45 00 6c 00 65 00 63 00 74 00 72 00 75 00 6d 00 2e 00 65 00 78 00 65 00 } //1 Electrum.exe
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}