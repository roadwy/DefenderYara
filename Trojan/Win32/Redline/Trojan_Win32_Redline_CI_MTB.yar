
rule Trojan_Win32_Redline_CI_MTB{
	meta:
		description = "Trojan:Win32/Redline.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c6 ba 98 c7 44 00 83 e0 ?? 8b cf 8a 98 ?? ?? ?? ?? 32 9e ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 88 ?? ?? ?? ?? ?? 46 59 81 fe ?? ?? ?? ?? 72 } //5
		$a_03_1 = {83 e9 06 8b c2 d3 e8 4d 24 ?? 0c ?? 88 03 ff 06 8b 1e 85 ed 7f } //5
		$a_81_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //1 VirtualProtectEx
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_81_2  & 1)*1) >=11
 
}