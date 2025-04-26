
rule Trojan_BAT_Formbook_NZ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 15 a2 09 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 83 00 00 00 10 00 00 00 32 01 00 00 f6 02 00 00 4f } //1
		$a_01_1 = {02 00 00 d6 00 00 00 90 05 00 00 36 00 00 00 0c 00 00 00 22 01 00 00 3b 02 00 00 0a 00 00 00 01 00 00 00 06 00 00 00 08 00 00 00 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Formbook_NZ_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {11 0b 11 07 61 13 0c 11 0c 11 09 59 } //2
		$a_81_1 = {31 39 30 33 31 31 30 32 2d 35 61 64 30 2d 34 65 64 35 2d 38 65 61 31 2d 31 32 66 66 31 61 30 38 63 65 37 64 } //1 19031102-5ad0-4ed5-8ea1-12ff1a08ce7d
		$a_81_2 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
		$a_81_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}