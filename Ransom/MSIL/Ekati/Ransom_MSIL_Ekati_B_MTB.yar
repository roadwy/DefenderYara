
rule Ransom_MSIL_Ekati_B_MTB{
	meta:
		description = "Ransom:MSIL/Ekati.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {65 6b 61 74 69 20 66 6f 72 20 66 69 6c 65 73 20 74 6f 20 62 65 20 65 6e 63 72 79 70 74 65 64 } //1 ekati for files to be encrypted
		$a_81_1 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 } //1 /c vssadmin.exe delete shadows
		$a_81_2 = {57 65 62 20 50 72 6f 74 65 63 74 65 64 20 62 6c 6f 63 6b 65 64 20 73 69 74 65 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Web Protected blocked site successfully
		$a_81_3 = {2e 65 6e 63 72 79 70 74 65 64 } //1 .encrypted
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}