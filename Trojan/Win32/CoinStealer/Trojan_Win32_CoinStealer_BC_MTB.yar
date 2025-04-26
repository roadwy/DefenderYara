
rule Trojan_Win32_CoinStealer_BC_MTB{
	meta:
		description = "Trojan:Win32/CoinStealer.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b c8 83 f1 3c 81 e9 ?? ?? ?? ?? 03 cf 81 e9 ?? ?? ?? ?? 89 4d } //1
		$a_03_1 = {2b c7 83 c0 4c 81 f0 ?? ?? ?? ?? 2b c6 33 05 ?? ?? ?? ?? 81 e8 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 89 45 } //1
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}