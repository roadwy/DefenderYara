
rule Trojan_Win32_Zusy_RE_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c1 6a 37 5e f7 f6 83 c2 32 66 31 54 4d ac 41 83 f9 17 7c e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zusy_RE_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 6f 72 6b 38 2e 64 6c 6c 00 4a 69 61 6a 6f 69 66 6a 61 65 67 65 61 69 6a 67 64 6a 00 4c 61 69 6f 66 67 6a 61 65 6f 69 67 65 61 67 68 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zusy_RE_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 04 3a 8b 18 89 ce 31 de 89 30 8d 47 04 89 c7 3b 7d fc 72 eb } //1
		$a_01_1 = {67 77 59 39 62 4d 55 63 63 67 67 67 68 51 46 34 6a 75 42 4b 51 37 49 6f 75 47 6b 79 50 52 70 65 69 70 35 } //1 gwY9bMUccggghQF4juBKQ7IouGkyPRpeip5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Zusy_RE_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 8b 08 89 4d e8 8b 55 f4 8b 02 c1 e0 06 8b 4d f4 8b 11 c1 ea 08 33 c2 8b 4d f4 8b 09 03 c8 8b 45 fc 33 d2 f7 75 ec 8b 45 08 03 0c 90 03 4d fc 8b 55 f0 8b 02 2b c1 8b 4d f0 89 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}