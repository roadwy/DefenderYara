
rule Trojan_Win32_Trayntadd{
	meta:
		description = "Trojan:Win32/Trayntadd,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {4d 73 74 72 61 79 2e 65 78 65 90 02 15 6d 73 75 70 64 61 74 61 2e 65 78 65 90 00 } //01 00 
		$a_03_1 = {77 73 6b 74 72 61 79 2e 65 78 65 90 02 15 6d 73 75 70 64 61 74 61 2e 65 78 65 90 00 } //01 00 
		$a_03_2 = {6d 73 6d 73 67 2e 65 78 65 90 02 15 6d 73 75 70 64 61 74 61 2e 65 78 65 90 00 } //03 00 
		$a_01_3 = {65 2e 65 6e 67 6c 61 6e 64 70 72 65 76 61 69 6c 2e 63 } //03 00  e.englandprevail.c
		$a_01_4 = {6f 6d 2f 70 72 6f 64 75 63 74 73 2f 64 72 69 76 65 2f 69 6e 64 65 78 2e 68 74 6d } //03 00  om/products/drive/index.htm
		$a_03_5 = {2f 2f 69 6e 64 65 78 2e 68 74 6d 90 02 05 6d 2e 63 6f 6d 2f 2f 61 72 74 69 63 6c 65 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}