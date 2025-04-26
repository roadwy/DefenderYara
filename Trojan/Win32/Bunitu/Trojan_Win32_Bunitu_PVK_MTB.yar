
rule Trojan_Win32_Bunitu_PVK_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.PVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {0f b6 44 24 07 88 99 ?? ?? ?? ?? 0f b6 9a ?? ?? ?? ?? 03 d8 81 f9 59 22 00 00 73 } //2
		$a_02_1 = {8b ff 33 3d ?? ?? ?? ?? 8b cf b8 04 00 00 00 03 c1 83 e8 04 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 } //2
		$a_02_2 = {b4 ca 48 21 5e da 08 ba ?? ?? ?? ?? 80 f3 09 eb } //2
		$a_02_3 = {f6 d2 0a ca 22 cb 88 08 83 c0 01 83 6c 24 ?? 01 89 44 24 ?? 0f 85 90 09 04 00 8b 44 24 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2) >=2
 
}