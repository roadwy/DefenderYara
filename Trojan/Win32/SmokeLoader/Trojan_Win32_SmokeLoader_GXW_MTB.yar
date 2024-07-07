
rule Trojan_Win32_SmokeLoader_GXW_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 45 f0 8b 4d f4 c1 e9 05 89 4d ec 8b 45 d4 01 45 ec 8b 55 e4 33 55 f0 89 55 e4 8b 45 e4 33 45 ec 89 45 e4 c7 05 90 01 04 00 00 00 00 8b 4d d0 2b 4d e4 89 4d d0 8b 45 d8 29 45 e8 e9 02 fb ff ff 90 00 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}