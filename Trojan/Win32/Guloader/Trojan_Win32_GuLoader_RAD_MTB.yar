
rule Trojan_Win32_GuLoader_RAD_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {73 75 70 70 72 65 73 73 61 6e 74 73 5c 50 79 74 68 6f 6e 69 63 61 6c 5c 73 6b 61 74 74 65 70 6f 6c 69 74 69 6b 73 } //1 suppressants\Pythonical\skattepolitiks
		$a_81_1 = {23 5c 73 74 72 61 66 75 64 6d 61 61 6c 69 6e 67 65 6e 5c 72 65 76 65 72 65 6e 74 } //1 #\strafudmaalingen\reverent
		$a_81_2 = {25 25 5c 76 69 6c 64 74 74 6c 6c 69 6e 67 65 72 2e 69 6e 69 } //1 %%\vildttllinger.ini
		$a_81_3 = {74 72 61 6e 73 76 65 72 73 61 6c 20 73 74 76 6e 69 6e 67 73 6d 61 6e 64 73 20 73 79 6b 6f 66 61 6e 74 65 72 6e 65 73 } //1 transversal stvningsmands sykofanternes
		$a_81_4 = {64 6f 75 70 69 6e 67 20 70 72 6f 6b 75 72 61 65 72 6e 65 20 76 69 63 65 6e 74 65 73 } //1 douping prokuraerne vicentes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}