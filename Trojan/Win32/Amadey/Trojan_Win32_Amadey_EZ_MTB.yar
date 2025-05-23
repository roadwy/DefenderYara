
rule Trojan_Win32_Amadey_EZ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 de 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 04 00 00 00 90 06 00 00 06 00 00 00 ee 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Amadey_EZ_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_81_0 = {62 67 70 6c 79 6f 66 6e } //2 bgplyofn
		$a_81_1 = {70 64 77 76 66 63 78 77 } //2 pdwvfcxw
		$a_81_2 = {4e 7a 41 7a 4d 54 41 79 4d 7a 55 35 4e 54 6c 61 4d 44 49 78 45 6a 41 51 42 67 4e 56 42 41 4d 4d 43 55 39 53 58 30 73 79 52 44 6c 4c 54 7a 45 63 4d 42 6f 47 41 31 55 45 43 67 77 54 54 33 4a 6c } //2 NzAzMTAyMzU5NTlaMDIxEjAQBgNVBAMMCU9SX0syRDlLTzEcMBoGA1UECgwTT3Jl
		$a_81_3 = {59 32 46 73 49 47 46 75 5a 43 42 46 62 47 56 6a 64 48 4a 76 62 6d 6c 6a 63 79 42 46 62 6d 64 70 62 6d 56 6c 63 6e 4d 73 49 45 6c 75 59 79 34 78 44 54 41 4c 42 67 4e 56 42 41 73 54 42 45 6c 46 } //1 Y2FsIGFuZCBFbGVjdHJvbmljcyBFbmdpbmVlcnMsIEluYy4xDTALBgNVBAsTBElF
		$a_81_4 = {62 47 56 6a 64 48 4a 70 59 32 46 73 59 57 35 6b 52 57 78 6c 59 33 52 79 62 32 35 70 59 33 4e 46 62 6d 64 70 62 6d 56 6c 63 6e 4e 4a 62 6d 4e 4a 52 55 56 46 55 6d 39 76 64 45 4e 42 4c 6d 4e 79 } //1 bGVjdHJpY2FsYW5kRWxlY3Ryb25pY3NFbmdpbmVlcnNJbmNJRUVFUm9vdENBLmNy
		$a_81_5 = {4f 69 38 76 63 47 74 70 4c 57 4e 79 62 43 35 7a 65 57 31 68 64 58 52 6f 4c 6d 4e 76 62 53 39 76 5a 6d 5a 73 61 57 35 6c 59 32 45 76 56 47 68 6c 53 57 35 7a 64 47 6c 30 64 58 52 6c 62 32 5a 46 } //1 Oi8vcGtpLWNybC5zeW1hdXRoLmNvbS9vZmZsaW5lY2EvVGhlSW5zdGl0dXRlb2ZF
		$a_81_6 = {4b 67 49 38 57 43 73 4b 62 41 30 5a 47 65 54 68 63 31 47 43 37 57 4e 33 6b 59 64 57 52 58 74 55 32 53 2b 61 75 4a 48 4d 70 41 31 37 44 4a 4d 79 4e 6d 73 6e 37 44 41 43 32 51 4b 42 67 44 62 33 } //1 KgI8WCsKbA0ZGeThc1GC7WN3kYdWRXtU2S+auJHMpA17DJMyNmsn7DAC2QKBgDb3
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=10
 
}