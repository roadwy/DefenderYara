
rule PWS_Win32_Piskitoy_A{
	meta:
		description = "PWS:Win32/Piskitoy.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {d7 00 00 00 8d 49 00 56 33 db ff 15 ?? ?? ?? ?? b9 01 80 ff ff 66 3b c1 0f 85 ?? 00 00 00 90 09 04 00 c7 44 24 } //1
		$a_03_1 = {eb 03 8d 49 00 8b c5 8d 70 01 8a 10 40 84 d2 75 f9 2b c6 2b c1 8a 54 28 ff 8b c5 88 54 0c ?? 41 8d 70 01 8b ff 8a 10 40 84 d2 } //1
		$a_03_2 = {43 3a 5c 5c 57 49 4e 44 4f 57 53 5c 5c 73 79 73 74 65 6d 33 32 5c 5c 43 61 74 52 6f 6f 74 32 5c 5c 7b 90 1e 08 00 2d 90 1e 04 00 2d 90 1e 04 00 2d 90 1e 04 00 2d 90 1e 0c 00 7d 5c 5c 73 79 73 63 6f 6e 66 69 67 2e 64 62 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}