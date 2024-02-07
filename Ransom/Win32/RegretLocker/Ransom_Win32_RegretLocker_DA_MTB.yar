
rule Ransom_Win32_RegretLocker_DA_MTB{
	meta:
		description = "Ransom:Win32/RegretLocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 65 67 72 65 74 4c 6f 63 6b 65 72 } //01 00  RegretLocker
		$a_81_1 = {2e 6d 6f 75 73 65 } //01 00  .mouse
		$a_81_2 = {48 4f 57 20 54 4f 20 52 45 53 54 4f 52 45 20 46 49 4c 45 53 2e 54 58 54 } //01 00  HOW TO RESTORE FILES.TXT
		$a_81_3 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 20 } //01 00  All your files were encrypted 
		$a_81_4 = {40 63 74 65 6d 70 6c 61 72 2e 63 6f 6d } //00 00  @ctemplar.com
	condition:
		any of ($a_*)
 
}