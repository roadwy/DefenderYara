
rule Trojan_Win32_Duqu_A{
	meta:
		description = "Trojan:Win32/Duqu.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 5c 00 52 00 65 00 61 00 6c 00 2d 00 54 00 69 00 6d 00 65 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //1 SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
		$a_01_1 = {8a 4d 08 88 48 08 88 58 09 8b 00 8b 10 8b c8 ff 52 04 } //1
		$a_03_2 = {8b 44 24 0c 03 c6 30 08 c1 c9 ?? 8b c1 0f af c1 33 d2 bf ?? ?? ?? ?? f7 f7 8b d1 69 d2 ?? ?? ?? ?? 8d 44 10 01 33 c8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}