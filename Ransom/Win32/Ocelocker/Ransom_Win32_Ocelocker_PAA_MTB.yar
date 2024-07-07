
rule Ransom_Win32_Ocelocker_PAA_MTB{
	meta:
		description = "Ransom:Win32/Ocelocker.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 61 6e 73 6f 6d 77 61 72 65 } //1 ransomware
		$a_01_1 = {4f 63 65 6c 6f 63 6b 65 72 2e 70 64 62 } //1 Ocelocker.pdb
		$a_01_2 = {57 72 69 74 69 6e 67 20 72 61 6e 73 6f 6d 20 6e 6f 74 65 } //1 Writing ransom note
		$a_01_3 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //1 All of your files are encrypted!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}