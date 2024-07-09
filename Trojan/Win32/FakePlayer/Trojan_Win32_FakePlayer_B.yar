
rule Trojan_Win32_FakePlayer_B{
	meta:
		description = "Trojan:Win32/FakePlayer.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f 85 c2 00 00 00 80 7d ?? 47 0f 85 ?? ?? 00 00 80 7d ?? 49 0f 85 ?? ?? 00 00 80 7d ?? 46 0f 85 ?? ?? 00 00 80 7d ?? 38 0f 85 ?? ?? 00 00 } //1
		$a_02_1 = {75 09 80 81 ?? ?? ?? 00 fd eb 33 8b ?? 6a 03 99 ?? f7 ?? 85 ?? 75 08 fe 89 ?? ?? ?? 00 eb 1f } //2
		$a_00_2 = {76 6e 65 74 73 65 72 76 69 63 65 73 2e 6c 30 30 38 36 2e 63 6f 6d 2e 63 6e } //1 vnetservices.l0086.com.cn
		$a_00_3 = {5c 4e 65 74 68 6f 6d 65 49 6e 66 6f 5c 4d 79 49 45 44 61 74 61 5c 6d 61 69 6e 2e 69 6e 69 } //1 \NethomeInfo\MyIEData\main.ini
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}