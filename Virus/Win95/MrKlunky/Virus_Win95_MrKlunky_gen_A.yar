
rule Virus_Win95_MrKlunky_gen_A{
	meta:
		description = "Virus:Win95/MrKlunky.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {81 7f 34 00 00 f7 bf 7c ca 8b 47 34 89 85 09 05 00 00 33 c0 66 8b 47 14 03 c7 83 c0 18 66 8b 4f 06 81 38 2e 65 64 61 75 09 81 78 04 74 61 00 00 74 10 83 c0 28 66 49 66 83 f9 00 75 e4 e9 7c 01 00 00 } //2
		$a_01_1 = {b9 e8 03 00 00 f2 ae 0b c9 0f 84 2c 02 00 00 81 7f fb 2e 45 58 45 0f 85 1f 02 00 00 b8 00 43 00 00 cd 20 32 00 40 00 0f 82 0e 02 00 00 51 b8 01 43 00 00 33 c9 cd 20 32 00 40 00 } //1
		$a_01_2 = {5c 5c 2e 5c 4d 72 4b 6c 75 6e 6b 79 2e 56 78 44 } //1 \\.\MrKlunky.VxD
		$a_01_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 56 78 44 5c 4d 72 4b 6c 75 6e 6b 79 } //1 SYSTEM\CurrentControlSet\Services\VxD\MrKlunky
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}