
rule Ransom_MSIL_Nitro_PAA_MTB{
	meta:
		description = "Ransom:MSIL/Nitro.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 2f 20 61 6e 79 20 61 6e 74 69 76 69 72 75 73 20 69 73 20 6f 66 66 } //1 Windows defender/ any antivirus is off
		$a_01_1 = {69 6d 70 6f 72 74 61 6e 74 20 64 6f 63 75 6d 65 6e 74 73 20 68 61 76 65 20 62 65 65 6e 20 6c 6f 63 6b 65 64 } //1 important documents have been locked
		$a_01_2 = {4e 69 74 72 6f 52 61 6e 73 6f 6d 77 61 72 65 2e 52 65 73 6f 75 72 63 65 73 } //1 NitroRansomware.Resources
		$a_01_3 = {46 6f 72 6d 55 72 6c 45 6e 63 6f 64 65 64 43 6f 6e 74 65 6e 74 } //1 FormUrlEncodedContent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}