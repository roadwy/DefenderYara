
rule Trojan_Win32_Alureon_gen_F{
	meta:
		description = "Trojan:Win32/Alureon.gen!F,SIGNATURE_TYPE_PEHSTR,07 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 20 49 4e 53 54 41 4c 4c 41 54 49 4f 4e 3a 20 43 6f 6d 70 6f 6e 65 6e 74 73 20 62 75 6e 64 6c 65 64 20 69 6e 74 6f 20 74 68 65 20 73 6f 66 74 77 61 72 65 20 6d 61 79 20 72 65 70 6f 72 74 20 74 6f 20 4c 69 63 65 6e 73 6f 72 } //2 SOFTWARE INSTALLATION: Components bundled into the software may report to Licensor
		$a_01_1 = {63 72 63 2e 65 78 65 00 70 61 63 6b 2e 62 69 6e 00 2d 6f 2b 20 2d 70 } //1
		$a_01_2 = {5c 73 65 74 75 70 20 31 2e 65 78 65 00 } //1
		$a_01_3 = {5c 73 65 74 75 70 20 32 2e 65 78 65 00 } //1
		$a_01_4 = {5c 63 72 63 2e 65 78 65 22 20 65 } //1 \crc.exe" e
		$a_01_5 = {70 61 63 6b 2e 62 69 6e 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}