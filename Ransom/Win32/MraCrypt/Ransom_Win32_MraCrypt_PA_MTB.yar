
rule Ransom_Win32_MraCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/MraCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 00 52 00 41 00 43 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 68 00 74 00 6d 00 6c 00 } //1 MRACReadMe.html
		$a_01_1 = {2e 00 4d 00 52 00 41 00 43 00 } //1 .MRAC
		$a_03_2 = {5c 4d 52 41 43 5c [0-10] 5c 4d 52 41 43 2e 70 64 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}