
rule Trojan_Win32_Zusy_RDA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 6f 73 69 6f 67 6a 69 6f 65 6a 68 67 65 68 } //1 Bosiogjioejhgeh
		$a_01_1 = {46 6f 64 6f 70 6b 77 6f 69 70 67 6f 69 77 65 6a } //1 Fodopkwoipgoiwej
		$a_01_2 = {49 75 69 6f 67 69 6f 73 65 6a 69 67 68 73 65 69 68 } //1 Iuiogiosejighseih
		$a_01_3 = {73 66 69 6f 67 6a 69 6f 67 6a 41 69 73 72 69 6f 73 65 6a 68 } //1 sfiogjiogjAisriosejh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}