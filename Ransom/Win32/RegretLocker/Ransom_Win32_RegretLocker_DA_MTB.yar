
rule Ransom_Win32_RegretLocker_DA_MTB{
	meta:
		description = "Ransom:Win32/RegretLocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {52 65 67 72 65 74 4c 6f 63 6b 65 72 } //1 RegretLocker
		$a_81_1 = {2e 6d 6f 75 73 65 } //1 .mouse
		$a_81_2 = {48 4f 57 20 54 4f 20 52 45 53 54 4f 52 45 20 46 49 4c 45 53 2e 54 58 54 } //1 HOW TO RESTORE FILES.TXT
		$a_81_3 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 20 } //1 All your files were encrypted 
		$a_81_4 = {40 63 74 65 6d 70 6c 61 72 2e 63 6f 6d } //1 @ctemplar.com
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}