
rule Trojan_Win32_BHO_AU{
	meta:
		description = "Trojan:Win32/BHO.AU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 6f 72 64 70 61 64 00 72 67 2e 64 61 74 00 00 5c 62 69 67 64 76 2e 64 61 74 } //1
		$a_00_1 = {49 6e 73 74 61 6c 6c 00 5c 74 6f 64 6f 2e 65 78 65 } //1
		$a_03_2 = {68 74 74 70 3a 2f 2f 34 2e 67 75 7a 68 69 6a 69 6a 69 6e 2e 63 6f 6d 2f 62 69 67 64 2f 90 02 08 2f 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 54 65 6d 70 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}