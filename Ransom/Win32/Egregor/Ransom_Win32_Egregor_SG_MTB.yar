
rule Ransom_Win32_Egregor_SG_MTB{
	meta:
		description = "Ransom:Win32/Egregor.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3a 5c 48 65 69 6c 20 45 67 72 65 67 6f 72 5c [0-08] 5c 66 69 63 6b 65 72 2e 70 79 } //1
		$a_81_1 = {2d 2d 64 75 62 69 73 74 65 69 6e 6d 75 74 74 65 72 66 69 63 6b 65 72 } //1 --dubisteinmutterficker
		$a_81_2 = {54 68 69 73 20 69 73 20 64 75 6d 6d 79 20 6d 65 73 73 61 67 65 62 6f 78 } //1 This is dummy messagebox
		$a_81_3 = {44 65 6c 65 74 69 6e 67 20 66 61 69 6c 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Deleting failed successfully
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}