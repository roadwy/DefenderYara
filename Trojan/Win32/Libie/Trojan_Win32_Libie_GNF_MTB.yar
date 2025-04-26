
rule Trojan_Win32_Libie_GNF_MTB{
	meta:
		description = "Trojan:Win32/Libie.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 53 55 5a 48 4a 58 45 48 } //1 aSUZHJXEH
		$a_01_1 = {5f 6e 4c 4d 71 4a 4a 75 4d 49 71 4a 42 71 4b 42 79 56 49 70 51 42 71 51 42 65 4a 38 64 4a 38 65 4d 39 55 } //1 _nLMqJJuMIqJBqKByVIpQBqQBeJ8dJ8eM9U
		$a_01_2 = {66 56 58 69 59 5a 5f 4f 50 5f 4f 50 66 56 57 66 53 54 5f 50 4f 63 57 59 54 4a 4c 72 69 6e } //1 fVXiYZ_OP_OPfVWfST_POcWYTJLrin
		$a_01_3 = {6d 50 41 72 53 44 70 52 42 71 52 41 6e 52 41 6f 53 41 6f 54 40 72 56 41 74 57 42 75 58 43 77 5a 45 77 } //1 mPArSDpRBqRAnRAoSAoT@rVAtWBuXCwZEw
		$a_01_4 = {2e 76 6d 70 30 } //1 .vmp0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}