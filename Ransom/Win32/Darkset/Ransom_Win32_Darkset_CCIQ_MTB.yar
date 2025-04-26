
rule Ransom_Win32_Darkset_CCIQ_MTB{
	meta:
		description = "Ransom:Win32/Darkset.CCIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_03_0 = {54 6f 75 63 68 4d 65 4e 6f 74 5f 2e 74 78 74 2e 5b [0-0f] 5d 2e 44 41 52 4b 53 45 54 } //5
		$a_01_1 = {2e 44 41 52 4b 53 45 54 5c 44 65 66 61 75 6c 74 49 63 6f 6e } //1 .DARKSET\DefaultIcon
		$a_01_2 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin.exe delete shadows /all /quiet
		$a_01_3 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //5 All your files have been encrypted
		$a_81_4 = {2e 44 41 52 4b 53 45 54 } //1 .DARKSET
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_81_4  & 1)*1) >=13
 
}