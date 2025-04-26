
rule Ransom_MSIL_Deniz_K_MSR{
	meta:
		description = "Ransom:MSIL/Deniz.K!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {44 00 65 00 6e 00 69 00 7a 00 5f 00 4b 00 69 00 7a 00 69 00 2e 00 4e 00 45 00 54 00 } //2 Deniz_Kizi.NET
		$a_00_1 = {52 00 65 00 61 00 64 00 4d 00 45 00 } //2 ReadME
		$a_02_2 = {65 00 76 00 62 00 [0-05] 74 00 6d 00 70 00 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_02_2  & 1)*1) >=5
 
}