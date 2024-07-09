
rule Trojan_Win32_Ramnit_I_bit{
	meta:
		description = "Trojan:Win32/Ramnit.I!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 4d 5a 00 00 66 39 01 75 f3 8b 41 3c 03 c1 81 38 50 45 00 00 75 e6 b9 ?? ?? ?? ?? 66 39 48 18 75 db } //1
		$a_03_1 = {8b 55 fc 83 c2 ?? 83 e2 ?? 8b 45 08 8b 4d fc 8b 75 08 8b 54 90 90 ?? 33 14 8e 8b 45 fc 83 c0 ?? 83 e0 ?? 8b 4d 08 89 54 81 ?? eb } //1
		$a_03_2 = {8b 55 0c 8b 45 08 8b 52 04 33 14 08 b8 ?? ?? ?? ?? 6b c8 ?? 8b 45 08 8b 0c 08 c1 e9 ?? 33 d1 b8 ?? ?? ?? ?? 6b c8 ?? 8b 45 08 8b 0c 08 c1 e1 ?? 33 d1 8b 45 10 89 50 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}