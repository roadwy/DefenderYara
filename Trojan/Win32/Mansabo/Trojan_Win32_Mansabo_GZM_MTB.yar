
rule Trojan_Win32_Mansabo_GZM_MTB{
	meta:
		description = "Trojan:Win32/Mansabo.GZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {6b 00 66 89 7c 24 48 66 ?? ?? ?? 50 33 00 66 ?? ?? ?? 52 32 00 66 ?? ?? ?? 54 66 ?? ?? ?? 56 66 ?? ?? ?? 5c 66 ?? ?? ?? 1a 66 ?? ?? ?? 1c 66 ?? ?? ?? 22 66 ?? ?? ?? 24 66 ?? ?? ?? 2a 66 ?? ?? ?? 2c 6d 00 66 ?? ?? ?? 2e 73 00 66 ?? ?? ?? 30 76 00 66 ?? ?? ?? 32 63 00 66 ?? ?? ?? 34 66 89 74 24 36 66 89 54 24 38 66 89 4c 24 3a 66 89 5c 24 40 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}