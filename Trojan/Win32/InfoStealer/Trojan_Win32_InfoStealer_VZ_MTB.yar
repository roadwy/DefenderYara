
rule Trojan_Win32_InfoStealer_VZ_MTB{
	meta:
		description = "Trojan:Win32/InfoStealer.VZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {d4 fe ff ff 83 c0 ?? 89 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 3b 4d 0c 73 22 0f b6 15 ?? ?? ?? ?? 8b 45 08 03 85 ?? ?? ?? ?? 0f b6 08 2b ca 8b 55 08 03 95 ?? ?? ?? ?? 88 0a eb c4 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_2 = {2e 70 64 62 } //1 .pdb
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}