
rule Trojan_Win32_Midie_SIBJ_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {79 7a 6c 68 62 78 78 68 2e 64 6c 6c } //1 yzlhbxxh.dll
		$a_03_1 = {33 c9 85 db 74 90 01 01 8a 04 39 90 02 20 34 a2 90 02 20 fe c0 34 4f 90 02 20 88 04 39 41 3b cb 72 90 01 01 6a 00 57 6a 00 ff 15 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Midie_SIBJ_MTB_2{
	meta:
		description = "Trojan:Win32/Midie.SIBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5c 62 72 65 61 6b 74 68 72 6f 75 67 68 2e 65 78 65 } //1 \breakthrough.exe
		$a_03_1 = {51 56 8d 8d 90 01 04 51 50 ff 15 90 01 04 b9 00 00 00 00 8a 84 0d 90 1b 00 81 f9 90 01 04 74 90 01 01 90 02 08 04 90 01 01 90 02 08 34 90 01 01 90 02 05 04 90 01 01 34 90 01 01 90 02 05 88 84 0d 90 1b 00 83 c1 01 90 18 8a 84 0d 90 1b 00 81 f9 90 1b 03 90 18 b0 00 b9 00 00 00 00 68 90 01 04 68 90 01 04 ff 15 90 01 04 50 ff 15 90 01 04 8d 4d 90 01 01 51 6a 40 56 8d 8d 90 1b 00 51 ff d0 8d 85 90 1b 00 ff d0 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}