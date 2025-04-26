
rule Trojan_Win32_Ursnif_AE_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 66 69 6e 67 65 72 5c 74 68 75 73 57 65 61 72 2e 70 64 62 } //1 \finger\thusWear.pdb
		$a_02_1 = {8b 5c 24 10 8b 1b 8b fd 2b 3d ?? ?? ?? 00 8b c1 2b c6 4f 48 89 3d ?? ?? ?? 00 89 1d ?? ?? ?? 00 81 fe ?? ?? ?? ?? 75 } //1
		$a_02_2 = {8b 5c 24 10 81 c1 ?? ?? ?? ?? 89 0d ?? ?? ?? 00 89 0b 0f b6 0d ?? ?? ?? 00 81 f9 ?? ?? ?? ?? 75 ?? 8d 0c 00 2b cf 8d b9 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}