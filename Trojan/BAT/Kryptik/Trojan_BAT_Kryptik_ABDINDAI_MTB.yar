
rule Trojan_BAT_Kryptik_ABDINDAI_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.ABDINDAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 "
		
	strings :
		$a_01_0 = {24 32 34 38 36 38 36 36 66 2d 35 64 37 32 2d 34 66 64 64 2d 61 38 62 66 2d 38 65 31 35 36 35 39 63 34 66 30 31 } //10 $2486866f-5d72-4fdd-a8bf-8e15659c4f01
		$a_01_1 = {53 6f 72 74 43 6f 6d 70 61 72 61 74 6f 72 } //1 SortComparator
		$a_01_2 = {53 65 74 43 6f 6d 70 61 72 61 74 6f 72 } //1 SetComparator
		$a_01_3 = {52 65 73 6f 6c 76 65 49 6d 70 6f 72 74 65 72 } //1 ResolveImporter
		$a_01_4 = {43 6f 75 6e 74 49 6d 70 6f 72 74 65 72 } //1 CountImporter
		$a_01_5 = {50 75 73 68 49 6d 70 6f 72 74 65 72 } //1 PushImporter
		$a_01_6 = {46 69 6e 64 49 6d 70 6f 72 74 65 72 } //1 FindImporter
		$a_01_7 = {49 6e 73 74 61 6e 74 69 61 74 65 49 6d 70 6f 72 74 65 72 } //1 InstantiateImporter
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=17
 
}