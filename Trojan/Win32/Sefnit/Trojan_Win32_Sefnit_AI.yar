
rule Trojan_Win32_Sefnit_AI{
	meta:
		description = "Trojan:Win32/Sefnit.AI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 ff 45 e8 83 f8 05 7e (90 09 10 00 ff 15|90 09 0d 00 57 ff (|) d6 d3) } //1
		$a_01_1 = {57 ff d6 8b c3 43 83 f8 05 7e } //1
		$a_01_2 = {47 6c 6f 62 61 6c 5c 56 42 6f 78 53 65 72 76 69 63 65 2e 65 78 65 00 } //1
		$a_01_3 = {5c 6f 75 74 70 75 74 5c 4d 69 6e 53 69 7a 65 52 65 6c 5c 75 70 64 72 65 6d 2e 70 64 62 } //3 \output\MinSizeRel\updrem.pdb
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3) >=4
 
}