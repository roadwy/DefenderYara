
rule Ransom_Win32_Clown_A_MSR{
	meta:
		description = "Ransom:Win32/Clown.A!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 67 2e 74 78 74 2e 63 6c 6f 77 6e } //1 bg.txt.clown
		$a_01_1 = {21 21 21 20 52 45 41 44 20 54 48 49 53 20 21 21 21 2e 68 74 61 } //1 !!! READ THIS !!!.hta
		$a_01_2 = {48 4f 57 20 54 4f 20 52 45 43 4f 56 45 52 20 45 4e 43 52 59 50 54 45 44 20 46 49 4c 45 53 2e 74 78 74 } //1 HOW TO RECOVER ENCRYPTED FILES.txt
		$a_03_3 = {5c 54 68 65 44 4d 52 5f 45 6e 63 72 79 70 74 65 72 5c [0-10] 5c 54 68 65 44 4d 52 5f 45 6e 63 72 79 70 74 65 72 2e 70 64 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}