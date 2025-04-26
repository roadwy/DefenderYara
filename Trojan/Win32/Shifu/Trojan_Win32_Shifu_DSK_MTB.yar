
rule Trojan_Win32_Shifu_DSK_MTB{
	meta:
		description = "Trojan:Win32/Shifu.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d2 33 3d ?? ?? ?? ?? 8b cf b8 04 00 00 00 03 c1 83 e8 04 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 } //2
		$a_02_1 = {8b 16 81 c2 9c 43 cd 01 89 16 83 c6 04 83 e8 01 89 15 ?? ?? ?? ?? 75 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}