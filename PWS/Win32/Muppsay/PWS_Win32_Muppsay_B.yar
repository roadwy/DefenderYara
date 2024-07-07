
rule PWS_Win32_Muppsay_B{
	meta:
		description = "PWS:Win32/Muppsay.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 11 81 fa b8 00 00 00 74 04 33 c0 eb 1d } //1
		$a_01_1 = {60 b8 44 33 22 11 ff d0 61 68 78 56 34 12 c3 } //1
		$a_01_2 = {8b 4d 08 8b 55 0c 89 51 02 8b 45 08 8b 4d 10 89 48 0a 5d c2 0c 00 } //1
		$a_00_3 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 62 00 69 00 6e 00 } //1 \SystemRoot\temp\system.bin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}