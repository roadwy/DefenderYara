
rule Ransom_MSIL_Revilcrypt_PAA_MTB{
	meta:
		description = "Ransom:MSIL/Revilcrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 20 00 26 00 26 00 20 00 77 00 6d 00 69 00 63 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 } //1 vssadmin delete shadows /all /quiet && wmic shadowcopy delete
		$a_01_1 = {56 69 72 75 73 4d 53 49 4c 4e 6f 6d 69 6e 61 74 75 73 53 74 6f 72 6d 2e 70 64 62 } //1 VirusMSILNominatusStorm.pdb
		$a_01_2 = {2e 00 65 00 78 00 65 00 20 00 3e 00 3e 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //1 .exe >>autorun.inf
		$a_01_3 = {5c 00 4b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00 2e 00 65 00 78 00 65 00 } //1 \Kaspersky.exe
		$a_01_4 = {49 6e 66 65 63 74 6f 72 } //1 Infector
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}