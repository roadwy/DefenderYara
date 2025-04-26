
rule Trojan_Win32_Neoreblamy{
	meta:
		description = "Trojan:Win32/Neoreblamy,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {77 72 75 74 66 6b } //wrutfk  1
		$a_80_1 = {6e 79 6c 71 65 73 6f } //nylqeso  1
		$a_80_2 = {6c 6f 70 6e 62 64 } //lopnbd  1
		$a_80_3 = {67 69 74 67 61 68 63 } //gitgahc  1
		$a_80_4 = {53 68 6f 77 4f 77 6e 65 64 50 6f 70 75 70 73 } //ShowOwnedPopups  2
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*2) >=4
 
}