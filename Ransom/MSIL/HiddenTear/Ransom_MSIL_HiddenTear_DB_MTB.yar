
rule Ransom_MSIL_HiddenTear_DB_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {48 69 64 64 65 6e 54 65 61 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 HiddenTear.Properties.Resources
		$a_81_1 = {52 41 4e 53 4f 4d 5f 4e 4f 54 45 2e 74 78 74 } //1 RANSOM_NOTE.txt
		$a_81_2 = {2f 43 20 76 73 73 61 64 6d 69 6e 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //1 /C vssadmin Delete Shadows /All /Quiet
		$a_81_3 = {2e 4c 4f 43 4b 45 44 } //1 .LOCKED
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}