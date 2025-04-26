
rule Ransom_Win32_Hamster_AA_MTB{
	meta:
		description = "Ransom:Win32/Hamster.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 /c vssadmin.exe delete shadows /all /quiet
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 20 61 6c 6c 20 74 68 65 20 73 74 75 66 66 } //1 encrypted all the stuff
		$a_01_2 = {2e 00 68 00 61 00 6d 00 73 00 74 00 65 00 72 00 } //1 .hamster
		$a_01_3 = {48 00 6f 00 77 00 20 00 54 00 6f 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 2e 00 74 00 78 00 74 00 } //1 How To decrypt.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}