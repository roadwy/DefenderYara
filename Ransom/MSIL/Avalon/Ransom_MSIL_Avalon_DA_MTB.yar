
rule Ransom_MSIL_Avalon_DA_MTB{
	meta:
		description = "Ransom:MSIL/Avalon.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 Your files are encrypted
		$a_81_1 = {41 76 61 6c 6f 6e 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 Avalon Ransomware
		$a_81_2 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 @protonmail.com
		$a_81_3 = {2e 61 76 61 6c 6f 6e } //1 .avalon
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}