
rule Trojan_Win32_GuLoader_DE_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 6e 74 72 69 63 65 72 6e 65 2e 42 65 6e } //1 Montricerne.Ben
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 50 72 6f 63 65 6e 74 75 65 6c 6c 65 73 32 33 32 5c 46 72 61 66 61 6c 64 73 70 72 6f 63 65 6e 74 73 5c 46 6f 72 61 72 62 65 6a 64 65 6e 64 65 73 5c 49 6e 63 65 72 61 74 69 6f 6e } //1 Software\Procentuelles232\Frafaldsprocents\Forarbejdendes\Inceration
		$a_01_2 = {4b 6f 6d 6d 75 6e 69 6b 61 74 69 6f 6e 73 66 69 72 6d 61 65 74 5c 47 6c 64 73 74 6e 69 6e 67 65 72 73 2e 69 6e 69 } //1 Kommunikationsfirmaet\Gldstningers.ini
		$a_01_3 = {49 6e 74 65 72 63 61 6c 6d 5c 4b 6f 6d 6d 75 6e 69 6b 61 74 69 6f 6e 73 74 65 6b 6e 69 73 6b 5c 53 68 61 75 6c 69 6e 67 5c 53 74 64 64 6d 70 65 72 73 2e 4e 6f 6e } //1 Intercalm\Kommunikationsteknisk\Shauling\Stddmpers.Non
		$a_01_4 = {56 65 64 65 72 68 65 66 74 69 67 68 65 64 65 6e 5c 4d 65 64 65 61 73 5c 4d 61 6c 69 67 6e 6d 65 6e 74 5c 43 75 6c 6c 69 6f 6e 72 79 } //1 Vederheftigheden\Medeas\Malignment\Cullionry
		$a_01_5 = {65 6a 64 65 6e 64 65 73 5c 49 6e 63 65 72 61 74 69 6f 6e } //1 ejdendes\Inceration
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}