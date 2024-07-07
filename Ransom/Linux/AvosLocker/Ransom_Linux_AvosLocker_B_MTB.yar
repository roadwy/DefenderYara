
rule Ransom_Linux_AvosLocker_B_MTB{
	meta:
		description = "Ransom:Linux/AvosLocker.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 61 76 6f 73 6c 69 6e 75 78 24 } //1 .avoslinux$
		$a_01_1 = {2f 52 45 41 44 4d 45 5f 46 4f 52 5f 52 45 53 54 4f 52 45 } //1 /README_FOR_RESTORE
		$a_03_2 = {74 74 70 3a 2f 2f 61 76 6f 73 90 02 58 2e 6f 6e 69 6f 6e 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}