
rule Trojan_Win32_Zloader_GGT_MTB{
	meta:
		description = "Trojan:Win32/Zloader.GGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c1 8b f1 c1 f8 ?? 83 e6 ?? 8d 1c 85 ?? ?? ?? ?? c1 e6 ?? 8b 03 8a 44 30 ?? a8 01 0f 84 ?? ?? ?? ?? 33 ff 39 7d 10 89 7d f8 89 7d f0 75 07 } //10
		$a_01_1 = {37 6b 77 69 66 68 72 65 } //1 7kwifhre
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}