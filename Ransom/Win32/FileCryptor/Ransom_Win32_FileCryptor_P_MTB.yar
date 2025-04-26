
rule Ransom_Win32_FileCryptor_P_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 20 48 61 76 65 20 42 65 65 6e 20 48 61 63 6b 65 64 } //1 You Have Been Hacked
		$a_81_1 = {59 4f 55 52 20 42 49 54 43 4f 49 4e 20 41 44 44 52 45 53 53 } //1 YOUR BITCOIN ADDRESS
		$a_81_2 = {44 6f 6e 27 74 20 69 6e 66 65 63 74 20 61 67 61 69 6e } //1 Don't infect again
		$a_81_3 = {44 65 73 6b 74 6f 70 5c 52 45 41 44 4d 45 2e 74 78 74 } //1 Desktop\README.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}