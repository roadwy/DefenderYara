
rule Trojan_BAT_BadJoke_PZML_MTB{
	meta:
		description = "Trojan:BAT/BadJoke.PZML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 02 7b 05 00 00 04 6f 19 00 00 0a 00 02 28 22 00 00 0a 6f 23 00 00 0a 73 24 00 00 0a 6f 25 00 00 0a 00 28 26 00 00 0a 0d 12 03 28 27 00 00 0a 0a 28 26 00 00 0a 0d 12 03 28 28 00 00 0a 0b 7e 29 00 00 0a 28 02 00 00 06 0c 08 28 2a 00 00 0a 13 04 00 11 04 02 7b 02 00 00 04 06 07 6f 2b 00 00 0a 00 00 de 0d } //3
		$a_01_1 = {00 02 7b 06 00 00 04 6f 19 00 00 0a 00 02 73 1a 00 00 0a 7d 01 00 00 04 28 01 00 00 06 0a 06 28 02 00 00 06 0b 28 1d 00 00 0a 6f 1e 00 00 0a 13 04 12 04 28 1f 00 00 0a 0c 28 1d 00 00 0a 6f 1e 00 00 0a 13 04 12 04 28 20 00 00 0a } //3
		$a_00_2 = {24 32 35 65 31 65 66 63 30 2d 36 34 32 39 2d 34 65 37 32 2d 61 35 34 32 2d 64 36 66 65 30 66 35 61 30 31 32 32 } //2 $25e1efc0-6429-4e72-a542-d6fe0f5a0122
		$a_00_3 = {67 00 64 00 69 00 5f 00 74 00 65 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 gdi_test.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1) >=9
 
}