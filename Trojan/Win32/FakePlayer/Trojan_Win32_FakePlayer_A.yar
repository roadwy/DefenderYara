
rule Trojan_Win32_FakePlayer_A{
	meta:
		description = "Trojan:Win32/FakePlayer.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f 85 c2 00 00 00 80 7d ?? 47 0f 85 ?? ?? 00 00 80 7d ?? 49 0f 85 ?? ?? 00 00 80 7d ?? 46 0f 85 ?? ?? 00 00 80 7d ?? 38 0f 85 ?? ?? 00 00 } //1
		$a_03_1 = {75 09 80 81 ?? ?? ?? 00 fd eb 33 8b c1 6a 03 99 5f f7 ff 85 d2 75 08 fe 89 ?? ?? ?? 00 eb 1f } //2
		$a_00_2 = {5c 4d 79 49 45 44 61 74 61 5c 6d 61 69 6e 2e 69 6e 69 } //1 \MyIEData\main.ini
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_00_2  & 1)*1) >=3
 
}