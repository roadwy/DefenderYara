
rule Trojan_Win32_GuLoader_REF_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.REF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 61 72 62 65 6a 64 73 74 69 6d 65 72 6e 65 5c 4d 6f 64 65 72 6c 69 67 } //1 \arbejdstimerne\Moderlig
		$a_81_1 = {25 4e 6f 76 61 6c 69 61 30 25 5c 63 61 70 6f 5c 50 61 67 61 6e 69 73 65 64 } //1 %Novalia0%\capo\Paganised
		$a_81_2 = {2d 5c 76 69 72 6b 73 6f 6d 68 65 64 73 6f 72 64 6e 69 6e 67 65 72 6e 65 73 2e 69 6e 69 } //1 -\virksomhedsordningernes.ini
		$a_81_3 = {35 5c 72 69 6c 65 5c 64 75 61 6c 69 74 65 74 65 6e 73 2e 74 78 74 } //1 5\rile\dualitetens.txt
		$a_81_4 = {70 68 6c 65 62 6f 64 69 75 6d 20 72 65 77 65 64 73 20 67 6f 64 6b 65 6e 64 65 6c 73 65 73 6d 79 6e 64 69 67 68 65 64 65 72 6e 65 73 } //1 phlebodium reweds godkendelsesmyndighedernes
		$a_81_5 = {6f 76 65 72 73 74 74 65 72 74 65 6b 6e 69 6b 6b 65 72 73 20 72 65 6f 72 63 68 65 73 74 72 61 74 65 64 20 65 76 61 6e 67 65 6c 69 65 62 67 65 72 6e 65 } //1 overstterteknikkers reorchestrated evangeliebgerne
		$a_81_6 = {67 72 6e 73 65 6f 6d 72 61 61 64 65 74 73 } //1 grnseomraadets
		$a_81_7 = {73 6b 6a 74 65 6c 62 } //1 skjtelb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}