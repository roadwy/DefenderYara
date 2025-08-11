
rule Trojan_Win32_SystemBC_BW_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f0 85 c9 0f 88 ?? ?? 00 00 39 c1 0f 86 ?? ?? 00 00 89 c1 83 e1 1f 0f b6 89 ?? ?? ?? ?? 8b 55 ec 30 0c 02 40 3d ?? ?? ?? ?? 72 } //4
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}