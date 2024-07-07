
rule Trojan_Win32_Starcedor_C{
	meta:
		description = "Trojan:Win32/Starcedor.C,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 73 64 6f 6f 72 2e 63 6f 6d 2f 61 69 77 32 2e 70 68 70 00 } //1
		$a_01_1 = {2a 2e 73 74 61 72 73 64 6f 6f 72 2e 63 6f 6d 00 } //1
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4e 65 77 20 57 69 6e 64 6f 77 73 5c 41 6c 6c 6f 77 } //1 Software\Microsoft\Internet Explorer\New Windows\Allow
		$a_01_3 = {43 72 65 61 74 65 4d 75 74 65 78 41 00 } //1
		$a_01_4 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 00 } //1
		$a_01_5 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}