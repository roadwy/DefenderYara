
rule Trojan_Win32_GuLoader_RSO_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {76 61 6b 75 75 6d 65 72 73 5c 73 75 6e 64 68 65 64 73 70 6c 65 6a 65 72 73 6b 65 72 73 5c 53 6b 79 67 67 65 72 6e 65 } //1 vakuumers\sundhedsplejerskers\Skyggerne
		$a_81_1 = {41 6e 73 74 74 65 6c 73 65 73 70 6c 61 6e 65 72 73 5c 4d 65 74 61 6c 6c 6f 69 64 32 30 35 5c 53 65 70 74 69 63 73 } //1 Ansttelsesplaners\Metalloid205\Septics
		$a_81_2 = {25 75 6e 72 65 63 6b 69 6e 67 6e 65 73 73 25 5c 53 71 75 65 6c 63 68 79 5c 6b 6e 67 74 65 74 } //1 %unreckingness%\Squelchy\kngtet
		$a_81_3 = {69 6e 64 6d 75 72 65 74 20 67 61 72 61 67 65 6c 65 6a 65 6e 73 20 64 65 63 72 75 73 74 61 74 69 6f 6e } //1 indmuret garagelejens decrustation
		$a_81_4 = {6b 6f 6e 73 6f 6c 69 64 65 72 69 6e 67 65 72 6e 65 73 20 73 61 6d 6d 65 6e 73 61 74 74 65 73 } //1 konsolideringernes sammensattes
		$a_81_5 = {73 71 75 69 6c 67 65 65 73 2e 65 78 65 } //1 squilgees.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}