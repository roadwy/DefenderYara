
rule Trojan_Win32_Manggarypt_B_bit{
	meta:
		description = "Trojan:Win32/Manggarypt.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c7 8d 0c 37 99 f7 7d ?? 8a 44 15 ?? 32 04 19 88 01 } //1
		$a_03_1 = {3d 00 00 00 80 73 ?? 83 c0 02 03 c3 eb ?? 0f b7 c0 50 ff 75 ?? ff 15 ?? ?? ?? ?? 89 04 37 83 c6 04 8b 06 } //1
		$a_03_2 = {8a 11 8d 42 ?? 3c 19 77 03 80 c2 e0 88 11 41 80 39 00 75 ec } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}