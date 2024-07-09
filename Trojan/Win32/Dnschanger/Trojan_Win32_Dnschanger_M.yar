
rule Trojan_Win32_Dnschanger_M{
	meta:
		description = "Trojan:Win32/Dnschanger.M,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 66 69 6c 65 73 2f 63 6f 75 6e 74 2e 6a 70 67 } //1 /files/count.jpg
		$a_00_1 = {5c 4e 65 74 77 6f 72 6b 5c 43 6f 6e 6e 65 63 74 69 6f 6e 73 5c 50 62 6b 5c 72 61 73 70 68 6f 6e 65 2e 70 62 6b } //1 \Network\Connections\Pbk\rasphone.pbk
		$a_03_2 = {25 73 5c 25 63 25 63 25 63 25 63 25 63 2e 25 73 [0-10] 25 73 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 [0-10] 68 74 6d 6c 66 69 6c 65 } //1
		$a_03_3 = {8b c1 c6 07 ?? 2b c7 89 77 01 03 c6 75 ?? 8b c1 2b d8 c6 01 e8 8d 44 33 ?? 89 41 01 8d 46 fc bb ?? ?? ?? 00 89 85 ?? ?? ?? ff 8d 45 ?? 50 6a 40 53 56 ff 75 ?? 89 b5 ?? ?? ?? ff ff 15 ?? ?? ?? 00 85 c0 75 ?? ff 15 } //4
		$a_03_4 = {59 33 c0 8d bd ?? ?? ?? ff 80 a5 ?? ?? ?? ?? ?? f3 ab 66 ab aa 6a 3f 33 c0 59 8d bd ?? ?? ?? ff f3 ab 8b 35 ?? ?? ?? 00 68 ?? ?? ?? 00 66 ab aa 8b 7d 0c 8d 85 ?? ?? ?? ff 50 89 7d ?? ff ?? 8d 85 ?? ?? ?? ff 50 8d 85 ?? ?? ?? ff 68 ?? ?? ?? 00 50 ff 15 } //4
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*4+(#a_03_4  & 1)*4) >=10
 
}