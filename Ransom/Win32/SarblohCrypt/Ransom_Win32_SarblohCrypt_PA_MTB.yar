
rule Ransom_Win32_SarblohCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/SarblohCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 52 00 45 00 41 00 44 00 4d 00 45 00 5f 00 53 00 41 00 52 00 42 00 4c 00 4f 00 48 00 2e 00 74 00 78 00 74 00 } //3 \Desktop\README_SARBLOH.txt
		$a_01_1 = {73 00 61 00 72 00 62 00 6c 00 6f 00 68 00 } //1 sarbloh
		$a_01_2 = {59 00 4f 00 55 00 52 00 20 00 46 00 49 00 4c 00 45 00 53 00 20 00 41 00 52 00 45 00 20 00 4c 00 4f 00 43 00 4b 00 45 00 44 00 21 00 } //1 YOUR FILES ARE LOCKED!
		$a_01_3 = {59 00 4f 00 55 00 52 00 20 00 46 00 49 00 4c 00 45 00 53 00 20 00 41 00 52 00 45 00 20 00 47 00 4f 00 4e 00 45 00 21 00 21 00 21 00 } //1 YOUR FILES ARE GONE!!!
		$a_01_4 = {46 55 43 4b 49 4e 44 49 41 } //3 FUCKINDIA
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*3) >=5
 
}