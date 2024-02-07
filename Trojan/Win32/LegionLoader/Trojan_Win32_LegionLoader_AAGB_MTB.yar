
rule Trojan_Win32_LegionLoader_AAGB_MTB{
	meta:
		description = "Trojan:Win32/LegionLoader.AAGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {45 70 61 70 6f 61 65 6f 66 61 66 67 61 6a 64 69 } //02 00  Epapoaeofafgajdi
		$a_01_1 = {46 61 69 6f 66 6f 69 61 66 61 69 6f 65 6a 67 68 61 65 } //02 00  Faiofoiafaioejghae
		$a_01_2 = {49 69 61 64 69 66 6f 61 69 6f 64 66 6a 67 61 65 69 68 67 } //02 00  Iiadifoaiodfjgaeihg
		$a_01_3 = {4f 61 65 6f 70 69 66 67 61 65 6f 70 67 6a 61 } //02 00  Oaeopifgaeopgja
		$a_01_4 = {4f 61 6f 66 67 61 65 69 6f 67 6a 61 64 73 69 67 68 } //02 00  Oaofgaeiogjadsigh
		$a_01_5 = {4f 6f 73 61 67 69 73 6a 67 73 69 65 67 73 75 68 } //02 00  Oosagisjgsiegsuh
		$a_01_6 = {55 70 73 72 67 69 77 6f 73 65 72 67 6a 77 69 67 6a 61 64 73 66 } //00 00  Upsrgiwosergjwigjadsf
	condition:
		any of ($a_*)
 
}