
rule Trojan_Win32_Wantvi_I{
	meta:
		description = "Trojan:Win32/Wantvi.I,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {f7 75 18 8b 45 14 0f be 14 10 33 ca 8b 45 ?? 03 45 ?? 88 08 eb cb } //2
		$a_01_1 = {eb 09 8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 7d 0b 8b 55 08 03 55 fc c6 02 00 eb e4 } //2
		$a_03_2 = {eb 17 6a 00 6a 06 ff 15 ?? ?? ?? ?? 85 c0 75 04 33 c0 eb 05 b8 01 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1) >=3
 
}