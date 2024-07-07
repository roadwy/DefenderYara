
rule Ransom_MSIL_HiddenTear_PG_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 66 00 6f 00 72 00 3d 00 63 00 3a 00 20 00 2f 00 61 00 6c 00 6c 00 } //1 delete shadows /for=c: /all
		$a_01_1 = {59 00 4f 00 55 00 52 00 20 00 46 00 49 00 4c 00 45 00 53 00 20 00 48 00 41 00 56 00 45 00 20 00 42 00 45 00 45 00 4e 00 20 00 45 00 4e 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 } //1 YOUR FILES HAVE BEEN ENCRYPTED
		$a_01_2 = {2f 00 55 00 6e 00 6c 00 6f 00 63 00 6b 00 59 00 6f 00 75 00 72 00 46 00 69 00 6c 00 65 00 73 00 } //1 /UnlockYourFiles
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}