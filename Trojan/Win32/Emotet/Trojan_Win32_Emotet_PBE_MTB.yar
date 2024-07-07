
rule Trojan_Win32_Emotet_PBE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c2 99 bd 2c 4d 00 00 f7 fd a1 90 01 04 8d 04 42 2b c6 2b c1 03 44 24 90 01 01 8b 54 24 90 01 01 03 44 24 90 01 01 03 44 24 90 01 01 03 c7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_PBE_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.PBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 08 8b 55 90 01 01 33 c0 8a 04 0a 8b 4d 90 01 01 03 4d 90 01 01 33 d2 8a 11 33 c2 8b 0d 90 01 04 8b 11 8b 4d 90 01 01 88 04 11 90 00 } //1
		$a_02_1 = {0f b6 04 0b 03 c2 33 d2 f7 35 90 01 04 8a 04 0a 8b 55 90 01 01 32 04 17 8b 55 90 01 01 88 04 17 90 00 } //1
		$a_81_2 = {52 7b 77 25 6b 66 50 36 73 7c 53 48 49 42 78 78 6a 37 43 6b 42 75 39 51 74 7b 30 42 77 74 44 6c 57 7d 74 7b 73 36 52 68 52 32 72 6f 7c 44 51 40 71 70 7a 6d 76 4e 53 75 71 3f 75 56 4b 31 4a 54 40 7c 6b 72 49 4c } //1 R{w%kfP6s|SHIBxxj7CkBu9Qt{0BwtDlW}t{s6RhR2ro|DQ@qpzmvNSuq?uVK1JT@|krIL
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}