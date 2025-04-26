
rule Ransom_Win32_Purga_DA_MTB{
	meta:
		description = "Ransom:Win32/Purga.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //1 vssadmin.exe Delete Shadows /All /Quiet
		$a_81_1 = {53 61 6e 64 62 6f 78 20 64 65 74 65 63 74 65 64 2c 20 77 6f 72 6b 20 69 6e 74 65 72 72 75 70 74 65 64 21 } //1 Sandbox detected, work interrupted!
		$a_81_2 = {72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 4e 6f } //1 recoveryenabled No
		$a_81_3 = {62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 } //1 bootstatuspolicy ignoreallfailures
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}