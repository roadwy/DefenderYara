
rule Trojan_Win32_GuLoader_RAC_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {53 65 72 76 69 65 74 74 65 72 5c 66 6f 72 66 65 6e 64 73 5c 65 63 63 6c 65 73 69 61 65 } //1 Servietter\forfends\ecclesiae
		$a_81_1 = {54 61 74 61 72 69 73 6b 65 73 5c 67 65 72 6e 69 6e 67 65 72 73 5c } //1 Tatariskes\gerningers\
		$a_81_2 = {4b 6f 6e 64 69 63 79 6b 6c 65 6e 73 2e 69 6e 69 } //1 Kondicyklens.ini
		$a_81_3 = {25 61 66 76 69 6b 6c 69 6e 67 73 74 69 64 73 25 5c 66 6a 65 72 64 65 5c 64 72 69 66 74 73 6f 6d 6b 6f 73 74 6e 69 6e 67 73 } //1 %afviklingstids%\fjerde\driftsomkostnings
		$a_81_4 = {5c 72 61 73 68 65 72 5c 74 69 6c 66 72 65 64 73 73 74 69 6c 6c 65 6c 73 65 6e 2e 6a 70 67 } //1 \rasher\tilfredsstillelsen.jpg
		$a_81_5 = {25 74 69 6c 73 74 25 5c 73 6b 6f 6c 69 6e 67 73 67 72 75 70 70 65 72 } //1 %tilst%\skolingsgrupper
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}