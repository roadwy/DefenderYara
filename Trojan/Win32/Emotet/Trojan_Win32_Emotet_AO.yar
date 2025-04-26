
rule Trojan_Win32_Emotet_AO{
	meta:
		description = "Trojan:Win32/Emotet.AO,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 64 6f 65 73 5c 73 77 69 6d 5c 68 61 76 65 5c 53 6c 6f 77 5c 77 65 5c 6c 6f 6e 65 61 70 70 65 61 72 2e 70 64 62 } //1 c:\does\swim\have\Slow\we\loneappear.pdb
		$a_01_1 = {63 3a 5c 62 72 6f 61 64 5c 43 68 69 65 66 5c 6c 69 67 68 74 5c 73 74 65 65 6c 5c 54 65 6e 5c 4d 61 72 6b 5c 70 61 73 74 50 65 72 68 61 70 73 2e 70 64 62 } //1 c:\broad\Chief\light\steel\Ten\Mark\pastPerhaps.pdb
		$a_01_2 = {63 3a 5c 57 69 66 65 5c 53 75 62 73 74 61 6e 63 65 5c 6a 6f 62 5c 6d 6f 6f 6e 5c 77 6f 72 6b 5c 50 6f 73 74 5c 69 72 6f 6e 50 72 6f 63 65 73 73 2e 70 64 62 } //1 c:\Wife\Substance\job\moon\work\Post\ironProcess.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}