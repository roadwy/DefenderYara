
rule Trojan_Win64_Mabezat_RP_MTB{
	meta:
		description = "Trojan:Win64/Mabezat.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {51 74 66 69 51 6e 67 77 66 77 7e 46 } //1 QtfiQngwfw~F
		$a_01_1 = {4c 6a 79 55 77 74 68 46 69 69 77 6a 78 78 } //1 LjyUwthFiiwjxx
		$a_01_2 = {48 77 6a 66 79 6a 55 6e 75 6a } //1 HwjfyjUnuj
		$a_01_3 = {55 6a 6a 70 53 66 72 6a 69 55 6e 75 6a } //1 UjjpSfrjiUnuj
		$a_01_4 = {48 77 6a 66 79 6a 55 77 74 68 6a 78 78 5c } //1 HwjfyjUwthjxx\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}