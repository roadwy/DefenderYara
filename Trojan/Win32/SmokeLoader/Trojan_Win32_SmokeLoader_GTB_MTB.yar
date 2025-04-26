
rule Trojan_Win32_SmokeLoader_GTB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d ec 8b c3 d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 45 c4 89 45 f4 8b 45 e8 31 45 fc 8b 45 fc 31 45 f4 83 3d ?? ?? ?? ?? 0c 75 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}