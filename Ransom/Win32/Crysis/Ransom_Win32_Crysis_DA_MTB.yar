
rule Ransom_Win32_Crysis_DA_MTB{
	meta:
		description = "Ransom:Win32/Crysis.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {46 49 4c 45 53 20 45 4e 43 52 59 50 54 45 44 2e 74 78 74 } //1 FILES ENCRYPTED.txt
		$a_81_1 = {54 6f 75 63 68 4d 65 4e 6f 74 5f 2e 74 78 74 } //1 TouchMeNot_.txt
		$a_81_2 = {40 61 6f 6c 2e 63 6f 6d } //1 @aol.com
		$a_81_3 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin delete shadows /all /quiet
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}