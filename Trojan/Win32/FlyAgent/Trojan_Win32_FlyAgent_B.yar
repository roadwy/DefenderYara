
rule Trojan_Win32_FlyAgent_B{
	meta:
		description = "Trojan:Win32/FlyAgent.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 25 41 25 25 00 62 6f 64 79 00 69 6e 6e 65 72 48 54 4d 4c 00 } //1
		$a_01_1 = {5c 61 33 2e 69 6e 69 00 6e 00 67 00 } //1 慜⸳湩ing
		$a_03_2 = {14 00 00 00 50 ff 75 f4 e8 ?? ?? ?? ?? 83 c4 08 83 f8 00 b8 00 00 00 00 0f 94 c0 89 45 f0 8b 5d f4 85 db 74 09 53 e8 ?? ?? ?? ?? 83 c4 04 83 7d f0 00 0f 84 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}