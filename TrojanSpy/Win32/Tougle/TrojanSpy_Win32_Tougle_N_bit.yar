
rule TrojanSpy_Win32_Tougle_N_bit{
	meta:
		description = "TrojanSpy:Win32/Tougle.N!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {31 07 83 c7 04 e2 f9 } //1
		$a_03_1 = {76 19 8a 4c 35 ?? 32 0c 02 32 ca 46 83 fe 10 88 0c 02 75 02 33 f6 42 3b d3 72 e7 } //1
		$a_03_2 = {76 22 8b 55 ?? 8b 4e 04 8b 7d 08 03 c8 8b 12 8a 0c 39 03 d0 40 88 0c 1a 8b 0e 3b c1 72 e4 } //1
		$a_03_3 = {c7 06 47 65 74 57 89 5d ?? c7 45 ?? 77 54 68 72 c7 45 ?? 65 61 64 50 c7 45 ?? 72 6f 63 65 c7 45 ?? 73 73 49 64 ff 55 } //1
		$a_01_4 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e } //1 schtasks /create /tn
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}