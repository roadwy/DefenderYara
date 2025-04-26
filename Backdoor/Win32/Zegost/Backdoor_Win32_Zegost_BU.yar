
rule Backdoor_Win32_Zegost_BU{
	meta:
		description = "Backdoor:Win32/Zegost.BU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {f6 c4 80 74 ?? 6a 14 ff 15 ?? ?? ?? 00 66 85 c0 74 ?? 83 ff ff 7e ?? 83 fe 40 7e ?? 83 fe 5b 7d 10 } //1
		$a_00_1 = {68 04 01 00 00 50 c6 44 24 18 5c c6 44 24 1a 75 c6 44 24 1b 72 c6 44 24 1c 6c c6 44 24 1e 67 c6 44 24 1f 2e } //1
		$a_02_2 = {8a 08 83 c1 fe 83 f9 0d 0f 87 ?? ?? 00 00 ff 24 8d ?? ?? 40 00 40 8b ce 50 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}