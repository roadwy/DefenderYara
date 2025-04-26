
rule Trojan_Win32_Genome_C{
	meta:
		description = "Trojan:Win32/Genome.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 50 52 4f 47 52 41 7e 31 5c 57 69 6e 52 41 52 5c 64 6f 64 6f 2e 76 62 73 } //1 D:\PROGRA~1\WinRAR\dodo.vbs
		$a_01_1 = {25 73 5c 25 73 00 00 00 2e 65 78 65 00 00 00 00 61 64 6d 69 6e 6c 6f 67 2e 65 78 65 00 00 00 00 52 61 76 4d 6f 6e 44 2e 65 78 65 } //1
		$a_01_2 = {54 52 55 45 29 0d 0d 0a 09 09 09 09 09 09 09 09 20 57 73 63 72 69 70 74 2e 53 6c 65 65 70 20 33 30 30 30 30 30 0d 0a } //1
		$a_01_3 = {5c cc da d1 b6 c8 ed bc fe 00 00 00 cc da d1 b6 54 54 00 00 b0 c1 d3 ce e4 af c0 c0 c6 f7 00 00 ca c0 bd e7 d6 ae b4 b0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}