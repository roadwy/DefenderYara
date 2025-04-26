
rule Trojan_Win32_Fragtor_KUAA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.KUAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 73 75 67 73 68 65 75 67 68 41 78 75 66 68 73 72 75 68 67 43 } //1 FsugsheughAxufhsruhgC
		$a_01_1 = {47 68 73 72 67 75 73 72 65 67 68 41 79 64 62 73 64 66 75 67 73 72 6a } //1 GhsrgusreghAydbsdfugsrj
		$a_01_2 = {69 73 65 68 66 75 73 65 68 67 73 67 68 5f 73 67 68 75 73 68 67 } //1 isehfusehgsgh_sghushg
		$a_01_3 = {76 62 75 73 75 67 68 73 5f 73 75 72 67 68 73 75 72 68 } //1 vbusughs_surghsurh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}