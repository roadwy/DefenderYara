
rule Trojan_Win32_Stealer_CB_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {30 c4 88 f0 34 ?? 88 e7 30 c7 20 e7 88 f0 34 ?? 24 ?? 88 d4 80 f4 ?? 88 85 } //1
		$a_03_1 = {89 c1 81 e9 ?? ?? ?? ?? 89 45 ?? 89 4d ?? 0f 84 } //1
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //2 VirtualProtect
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}