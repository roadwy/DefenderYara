
rule Trojan_Win32_Cimiwa_A{
	meta:
		description = "Trojan:Win32/Cimiwa.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 69 6e 67 64 3f } //1 pingd?
		$a_01_1 = {26 6b 65 79 66 72 6f 6d 3d } //1 &keyfrom=
		$a_01_2 = {25 73 69 65 74 61 72 2e 69 6e 66 } //1 %sietar.inf
		$a_01_3 = {73 68 69 74 2e 65 78 65 } //1 shit.exe
		$a_01_4 = {47 45 54 20 2f 77 2e 67 69 66 3f 6d 65 73 73 61 67 65 } //1 GET /w.gif?message
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}