
rule Trojan_Win32_CryptInject_BE_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c8 0b 98 7f b8 c6 ee 57 15 81 45 ?? be 6c ?? 28 81 e3 15 2d 0d 0f 81 6d ?? 36 18 c4 05 81 f3 26 ed 5f 56 81 45 ?? 40 b7 cb 5c 8b 5d ?? 8b 45 ?? 33 d6 2b 4d ?? 40 2b fa 89 4d ?? 89 45 ?? 3b 45 ?? 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_CryptInject_BE_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {41 50 50 44 41 54 41 [0-20] 25 73 5c 62 6f 78 } //1
		$a_02_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 [0-50] 41 70 70 49 6e 69 74 5f 44 4c 4c 73 [0-20] 25 73 5c 62 6f 78 2e 6c 6e 6b } //1
		$a_02_2 = {6c 61 75 6e 63 68 [0-20] 50 72 6f 67 72 61 6d 46 69 6c 65 73 [0-20] 64 72 6f 70 [0-20] 44 4c 4c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule Trojan_Win32_CryptInject_BE_MTB_3{
	meta:
		description = "Trojan:Win32/CryptInject.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {56 00 b4 00 69 00 b4 00 72 00 b4 00 74 00 b4 00 75 00 b4 00 61 00 b4 00 6c 00 b4 00 50 00 b4 00 72 00 b4 00 6f 00 b4 00 74 00 b4 00 65 00 b4 00 63 00 b4 00 74 00 b4 } //1
		$a_01_1 = {56 00 25 00 69 00 25 00 72 00 25 00 74 00 25 00 75 00 25 00 61 00 25 00 6c 00 25 00 41 00 25 00 6c 00 25 00 6c 00 25 00 6f 00 25 00 63 00 25 00 45 00 25 00 78 00 25 00 } //1 V%i%r%t%u%a%l%A%l%l%o%c%E%x%
		$a_00_2 = {47 00 5e 00 65 00 5e 00 74 00 5e 00 54 00 5e 00 69 00 5e 00 63 00 5e 00 6b 00 5e 00 43 00 5e 00 6f 00 5e 00 75 00 5e 00 6e 00 5e 00 74 00 5e } //1
		$a_01_3 = {4d 00 40 00 69 00 40 00 63 00 40 00 72 00 40 00 6f 00 40 00 73 00 40 00 6f 00 40 00 66 00 40 00 74 00 40 00 } //1 M@i@c@r@o@s@o@f@t@
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}