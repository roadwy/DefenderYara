
rule Trojan_Win32_Enfal_H{
	meta:
		description = "Trojan:Win32/Enfal.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 67 69 2d 62 69 6e 2f 63 6c 6e 70 70 35 2e 63 67 69 00 } //1
		$a_03_1 = {63 67 69 2d 62 69 6e 2f ?? 77 70 71 ?? 2e 63 67 69 } //1
		$a_01_2 = {4e 46 61 6c 2e 65 78 65 00 00 00 00 } //1
		$a_00_3 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //1 software\microsoft\windows\currentversion\run
		$a_01_4 = {2f 43 6d 77 68 69 74 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}