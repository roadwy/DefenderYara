
rule Trojan_Win32_Guloader_SPY_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 73 6f 6d 6e 69 61 74 65 5c 73 61 6c 67 73 73 69 74 75 61 74 69 6f 6e 73 2e 4f 70 61 31 34 39 } //1 \somniate\salgssituations.Opa149
		$a_01_1 = {5c 73 63 61 70 68 69 73 6d 5c 75 6e 6f 70 74 69 6d 69 73 74 69 63 61 6c 6c 79 2e 69 6e 69 } //1 \scaphism\unoptimistically.ini
		$a_01_2 = {5c 66 6c 61 76 6f 75 72 6c 65 73 73 65 73 5c 42 61 75 62 6c 69 6e 67 5c 53 61 6d 6d 65 6e 72 75 6c 6c 65 6e 64 65 2e 69 6e 69 } //1 \flavourlesses\Baubling\Sammenrullende.ini
		$a_01_3 = {5c 48 6f 74 65 6c 73 5c 50 72 6f 66 65 74 69 65 72 6e 65 73 5c 67 6c 61 73 73 6b 61 61 72 65 6e 65 5c 73 6b 6f 6e 72 6f 67 73 2e 41 75 73 31 35 35 } //1 \Hotels\Profetiernes\glasskaarene\skonrogs.Aus155
		$a_01_4 = {61 66 6e 61 7a 69 66 69 63 65 72 65 64 65 2e 64 6c 6c } //1 afnazificerede.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}