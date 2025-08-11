
rule Trojan_Win32_GuLoader_RAA_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 70 6c 61 64 73 68 6f 6c 64 65 72 65 73 5c 63 69 74 68 72 65 6e 73 5c 6d 6f 6e 6f 6d 65 74 61 6c 69 73 6d } //1 \pladsholderes\cithrens\monometalism
		$a_81_1 = {25 54 65 73 74 6b 72 73 6c 65 72 6e 65 73 25 5c 74 65 68 74 74 65 6e } //1 %Testkrslernes%\tehtten
		$a_81_2 = {73 77 61 67 62 65 6c 6c 69 65 73 20 64 65 71 75 65 75 65 64 } //1 swagbellies dequeued
		$a_81_3 = {64 79 76 65 6c 20 61 70 6f 74 65 6b 65 72 64 69 73 63 69 70 6c 65 6e } //1 dyvel apotekerdisciplen
		$a_81_4 = {6d 65 6e 75 61 6c 74 65 72 6e 61 74 69 76 65 72 6e 65 73 2e 65 78 65 } //1 menualternativernes.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}