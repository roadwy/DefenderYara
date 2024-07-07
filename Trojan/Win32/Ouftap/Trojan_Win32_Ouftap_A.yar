
rule Trojan_Win32_Ouftap_A{
	meta:
		description = "Trojan:Win32/Ouftap.A,SIGNATURE_TYPE_PEHSTR_EXT,17 00 12 00 0d 00 00 "
		
	strings :
		$a_01_0 = {83 e9 08 8b 1e 81 36 af 17 e5 38 31 5e 04 89 fe d1 cb fc ac 32 c1 32 c7 00 d8 aa c1 cb 03 81 f3 27 12 85 d4 81 c3 a1 53 cd 43 e2 e7 } //8
		$a_01_1 = {74 61 70 69 33 32 6d 75 74 65 78 } //8 tapi32mutex
		$a_01_2 = {4d 61 73 6b 3d } //1 Mask=
		$a_01_3 = {42 72 6f 61 64 63 61 73 74 3d } //1 Broadcast=
		$a_01_4 = {6d 61 63 20 6e 6f 74 20 66 6f 75 6e 64 } //1 mac not found
		$a_01_5 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 Toolhelp32ReadProcessMemory
		$a_01_6 = {41 55 54 4f 4d 41 54 49 4f 4e } //1 AUTOMATION
		$a_01_7 = {45 4d 42 45 44 44 49 4e 47 } //1 EMBEDDING
		$a_01_8 = {52 45 47 53 45 52 56 45 52 } //1 REGSERVER
		$a_01_9 = {5c 6d 69 70 73 2e 62 69 6e } //1 \mips.bin
		$a_01_10 = {5c 69 73 75 6e 69 6e 73 74 2e 62 69 6e } //1 \isuninst.bin
		$a_01_11 = {5c 5c 2e 5c 46 61 44 65 76 69 63 65 30 } //1 \\.\FaDevice0
		$a_01_12 = {32 34 68 2d 4f 6b } //1 24h-Ok
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*8+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=18
 
}