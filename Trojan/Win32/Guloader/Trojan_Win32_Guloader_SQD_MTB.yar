
rule Trojan_Win32_Guloader_SQD_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SQD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {61 6e 74 69 6b 69 73 65 72 5c 6b 6f 6c 6f 6e 6e 65 61 66 73 74 61 6e 64 } //2 antikiser\kolonneafstand
		$a_81_1 = {73 70 65 6e 63 65 72 6b 6a 6f 6c 65 5c 65 70 69 67 79 6e 79 2e 6a 70 67 } //1 spencerkjole\epigyny.jpg
		$a_81_2 = {54 76 61 6e 67 73 66 6a 65 72 6e 65 6c 73 65 6e 73 2e 73 75 62 } //1 Tvangsfjernelsens.sub
		$a_81_3 = {4b 6f 67 67 65 72 65 74 73 2e 68 61 72 } //1 Koggerets.har
		$a_81_4 = {61 6b 73 65 6c 74 72 79 6b 6b 65 6e 65 2e 62 65 73 } //1 akseltrykkene.bes
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=6
 
}