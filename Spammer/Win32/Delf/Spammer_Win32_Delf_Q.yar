
rule Spammer_Win32_Delf_Q{
	meta:
		description = "Spammer:Win32/Delf.Q,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {4b 85 db 7c 90 01 01 8b 90 01 02 c1 e0 06 03 d8 89 90 01 02 83 c7 06 83 ff 08 7c 90 01 01 83 ef 08 8b cf 8b 90 01 02 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 90 01 02 5a 8b ca 99 f7 f9 89 90 01 02 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 90 00 } //3
		$a_01_1 = {79 5a 50 43 74 67 36 4e 78 37 36 31 44 63 39 37 45 68 71 } //1 yZPCtg6Nx761Dc97Ehq
		$a_01_2 = {42 78 6e 56 7a 75 62 54 41 77 6e 59 42 32 6e 56 7a 4e 71 55 79 38 36 54 } //1 BxnVzubTAwnYB2nVzNqUy86T
		$a_01_3 = {32 61 6c 74 72 66 6b 69 6e 64 79 73 61 64 76 6e 71 77 33 6e 65 72 61 73 64 66 } //2 2altrfkindysadvnqw3nerasdf
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=7
 
}