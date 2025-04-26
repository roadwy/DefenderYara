
rule Trojan_Win32_Emotetcrypt_HC_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 04 80 03 d8 a1 ?? ?? ?? ?? 0f af d9 6b c9 fd 03 eb 8d 5e 04 0f af d8 2b cb 2b ce 03 ca 8d 50 02 0f af d6 8d 04 42 8d 04 80 8d 4c 8d 00 2b c8 8b 44 24 24 8a 18 8a 0c 39 32 d9 8b 4c 24 34 88 18 } //1
		$a_81_1 = {53 2b 6a 4f 6c 43 47 66 64 36 68 68 65 43 2b 79 65 61 4d 37 28 73 35 70 52 36 33 6f 4e 68 4d 50 62 74 2a 71 33 51 68 58 78 2a 26 68 4d 29 39 26 26 3c 45 72 35 5e 55 37 72 6c 21 3c 52 56 5a 42 29 77 6e 73 49 32 61 52 57 40 40 38 34 77 53 55 3f 32 } //1 S+jOlCGfd6hheC+yeaM7(s5pR63oNhMPbt*q3QhXx*&hM)9&&<Er5^U7rl!<RVZB)wnsI2aRW@@84wSU?2
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}