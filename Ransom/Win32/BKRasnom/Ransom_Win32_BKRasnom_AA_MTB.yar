
rule Ransom_Win32_BKRasnom_AA_MTB{
	meta:
		description = "Ransom:Win32/BKRasnom.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 42 4b 52 61 6e 73 6f 6d 77 61 72 65 5c 52 65 6c 65 61 73 65 5c 42 4b 52 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //1 \BKRansomware\Release\BKRansomware.pdb
		$a_00_1 = {67 00 6d 00 72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 74 00 78 00 74 00 2e 00 68 00 61 00 69 00 6e 00 68 00 63 00 } //1 gmreadme.txt.hainhc
		$a_01_2 = {5c 53 59 53 54 45 4d 33 32 5c 63 68 63 70 2e 63 6f 6d 2e 68 61 69 6e 68 63 } //1 \SYSTEM32\chcp.com.hainhc
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}