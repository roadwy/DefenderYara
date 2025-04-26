
rule Trojan_Win32_Alureon_GB{
	meta:
		description = "Trojan:Win32/Alureon.GB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {25 53 61 66 67 3f 69 64 3d 25 73 26 61 66 66 3d 25 75 00 } //1
		$a_01_1 = {c6 45 ec e9 8b 4d 10 2b 4d fc 83 e9 05 89 4d ed } //1
		$a_03_2 = {6a 2a 56 ff 15 ?? ?? ?? ?? 59 59 89 44 24 1c 3b c3 74 02 88 18 6a 3c } //1
		$a_00_3 = {71 00 61 00 7a 00 78 00 73 00 77 00 5f 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}